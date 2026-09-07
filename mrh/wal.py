"""The C5 evidence path — Appendix R, the high-performance evidence pattern.

Appendix R splits recording a governance event into a synchronous gate and an
asynchronous tail:

    steps 1-6  construct, chain, sign, write to a local append-only WAL, fsync.
               These MUST complete before the next governed action is admitted.
    steps 7-9  batch, replicate to the central store, record proof of replication.
               These MAY complete after the next action has proceeded.

Two things this module refuses to do, both named in R.5 as non-conformant:

  * acknowledge a write that reached the OS page cache but not durable storage --
    `append()` calls `os.fsync` and only then returns;
  * use central replication as the gate -- `replicate()` is explicitly not on the
    admission path, and an unreplicated event is a full-status evidence record
    (R.5, last bullet), not a provisional one.

R.4 invariant 4 is the one most easily lost in a demonstrator: the WAL signing key
"MUST NOT reside in the governed agent's own trust domain", because a journal signed
with a key the compromised agent can read is forgeable by the principal it exists to
hold accountable. `LocalSigner` therefore holds its key privately and exposes only
`sign`/`verify`; nothing in the harness can reach the key material. In a deployment it
stands for an HSM, a TPM-backed key, or a sidecar signer in a separate security
context -- not for a secret in the agent's process.
"""
import hashlib
import hmac
import json
import os

GENESIS = "0" * 64


def canon(obj):
    """Canonical serialization. Chain and signature are computed over this form."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LocalSigner(object):
    """A separately-trusted signer (Appendix R, invariant 4).

    HMAC-SHA256 with a demo key stands in for an asymmetric key in an HSM or TPM. The
    substitution is deliberate and it is the one place this harness is weaker than a
    deployment must be: an HMAC key verifies only to a holder of the same key, whereas
    R.4 requires an auditor to verify with the same registry used for central C5
    signatures. `algorithm` is recorded on every event so the record says what produced
    it (`event.signature_algorithm`, §4.7.1).
    """

    algorithm = "HMAC-SHA256-demo"

    def __init__(self, signer_id="c5-local-signer", epoch="e1", key=None):
        self.signer_id = signer_id
        self.epoch = epoch
        self.__key = key or b"CROA-MRH-WAL-DEMO-KEY-not-for-production"

    def sign(self, payload):
        return hmac.new(self.__key, canon(payload).encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        return hmac.compare_digest(self.sign(payload), signature)


class WalIntegrityError(Exception):
    """Raised on a gap, a reordering or a bad signature (R.4, invariant 3)."""


class WriteAheadLog(object):
    """Append-only, hash-chained, durably-written local evidence journal.

    `path=None` keeps the journal in memory, which is what the unit tests use; the
    durability gate is then a no-op and the object says so via `durable`.
    """

    def __init__(self, signer=None, path=None):
        self.signer = signer or LocalSigner()
        self.path = str(path) if path else None
        self.durable = self.path is not None
        self.records = []
        self._head = GENESIS

    # ------------------------------------------------------ R.3 steps 2-5
    def append(self, event):
        """Chain, sign and durably write one event. Returns the written record.

        The record is complete before it is chained: R.3 step 2 forbids writing a
        record with an unpopulated required field, so a caller that has not finished
        building the event has not reached step 3.
        """
        record = dict(event)
        record["event.chain_hash"] = self._head                       # step 3
        record["event.signer_id"] = self.signer.signer_id
        record["event.signer_epoch"] = self.signer.epoch
        record["event.signature_algorithm"] = self.signer.algorithm
        record["event.signature"] = self.signer.sign(record)          # step 4, covers chain_hash

        if self.path:                                                 # step 5
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, sort_keys=True) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())     # page cache is not durable storage (R.5)
            except OSError as exc:
                # R.3 step 5 / R.4 invariant 1: a failed durable write is fail-deny for
                # the *next* action, not a warning. The caller must not admit anything.
                raise WalIntegrityError("durable WAL write failed: %s" % exc)

        self.records.append(record)
        self._head = sha256(canon(record))
        return record

    # ---------------------------------------------------------- R.4 inv. 3, 7
    def verify(self, records=None):
        """Recompute the chain and every signature. Returns (ok, message).

        R.4 invariant 7 requires this to give the same answer against the local WAL and
        against the central store for the same period, which is why it takes the record
        sequence as an argument rather than reading `self.records` unconditionally.
        """
        seq = self.records if records is None else records
        prev = GENESIS
        for rec in seq:
            if rec.get("event.chain_hash") != prev:
                return False, "chain break at %s" % rec.get("event.id")
            unsigned = dict((k, v) for k, v in rec.items() if k != "event.signature")
            if not self.signer.verify(unsigned, rec.get("event.signature", "")):
                return False, "bad signature at %s" % rec.get("event.id")
            prev = sha256(canon(rec))
        return True, "chain verified: %d events, unbroken" % len(seq)

    def head(self):
        return self._head

    def since(self, index):
        return self.records[index:]


class CentralStore(object):
    """The replication target (R.3 steps 7-8).

    Off the admission path by construction: nothing here is called before an action is
    admitted. On receipt the store verifies chain continuity from the last event it
    already holds and rejects the batch on a gap -- R.3 step 8 -- because a store that
    accepts a gap silently is worse than one that has no events at all.
    """

    def __init__(self, signer):
        self.signer = signer
        self.records = []
        self.alerts = []
        self._head = GENESIS

    def receive(self, batch):
        """Accept a batch, or reject it and raise an operational alert."""
        prev = self._head
        for rec in batch:
            if rec.get("event.chain_hash") != prev:
                self.alerts.append("chain continuity broken at %s" % rec.get("event.id"))
                return False, "chain continuity broken at %s" % rec.get("event.id")
            unsigned = dict((k, v) for k, v in rec.items() if k != "event.signature")
            if not self.signer.verify(unsigned, rec.get("event.signature", "")):
                self.alerts.append("bad signature at %s" % rec.get("event.id"))
                return False, "bad signature at %s" % rec.get("event.id")
            prev = sha256(canon(rec))
        self.records.extend(batch)
        self._head = prev
        return True, "accepted %d events" % len(batch)


class Replicator(object):
    """Drives R.3 steps 7-9. Deliberately manual: nothing calls it on the hot path.

    `lag()` is the governed operational parameter of R.4 invariant 5 -- declared,
    monitored, and alerted on when it is breached. The harness exposes it so a scenario
    can show that replication lag is a *measured* quantity rather than an assumption.
    """

    def __init__(self, wal, central, max_lag=64):
        self.wal = wal
        self.central = central
        self.max_lag = max_lag
        self.replicated = 0
        self.alerts = []

    def lag(self):
        return len(self.wal.records) - self.replicated

    def check_lag(self):
        if self.lag() > self.max_lag:
            msg = "replication lag %d exceeds declared maximum %d" % (self.lag(), self.max_lag)
            self.alerts.append(msg)
            return False, msg
        return True, "lag %d within declared maximum %d" % (self.lag(), self.max_lag)

    def flush(self):
        """Steps 7-9. Returns (ok, message)."""
        batch = self.wal.since(self.replicated)
        if not batch:
            return True, "nothing to replicate"
        ok, msg = self.central.receive(batch)
        if not ok:
            self.alerts.append(msg)
            return False, msg
        self.replicated += len(batch)
        return True, msg

    def reconcile(self):
        """R.4 invariant 7: the same verification must hold on both sides.

        Divergence between the local WAL and the central store for the same period is
        itself a conformance failure and is reported as one.
        """
        ok_local, msg_local = self.wal.verify()
        ok_central, msg_central = self.wal.verify(self.central.records)
        if not ok_local:
            return False, "local WAL: %s" % msg_local
        if not ok_central:
            return False, "central store: %s" % msg_central
        n = len(self.central.records)
        if self.wal.records[:n] != self.central.records:
            return False, "local WAL and central store diverge over the replicated period"
        return True, "local and central agree over %d replicated events (%d pending)" % (
            n, self.lag())
