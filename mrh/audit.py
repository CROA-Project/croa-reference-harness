"""C5 — Audit & Provenance Store: append-only, hash-chained, signed governance events.

v1.0.1. Three changes from the previous version, all of them driven by the §4.7.1
field table rather than by taste:

  * `event.emitter_signature` is now `event.signature`, and every event carries the
    full signature block -- `event.signer_id`, `event.signer_epoch`,
    `event.signature_algorithm`.
  * `CC_COMPILED` is `ECC_COMPILED`, `event.cc_id` is `event.ecc_id`, and the block
    reasons are the `ECC_*` set.
  * The three effect-attestation types exist: `EXECUTION_COMPLETED`,
    `EXECUTION_FAILED` and `EFFECT_ATTESTED`. They are emitted post-execution and say
    what actually happened on the target system, which `EXECUTION_AUTHORIZED` does
    not: authorizing an operation and the operation having an effect are different
    facts, and only the second is evidence of an effect.

The store writes through `mrh.wal.WriteAheadLog` (Appendix R), so recording an event
is a durable local commit and not an in-memory append. `emit()` returns only after
that commit, which is what makes it usable as the I6 gate: the caller may admit the
next governed action once `emit()` has returned, and not before.
"""
import datetime
import uuid

from .wal import CentralStore, LocalSigner, Replicator, WriteAheadLog, canon, sha256

GENESIS = "0" * 64

# §4.7.1, closed enumeration.
EVENT_TYPES = (
    "PERMIT", "DENY", "ECC_COMPILED", "EXECUTION_AUTHORIZED", "EXECUTION_BLOCKED",
    "CONTEXT_FAILURE", "TRAJECTORY_ALERT", "ADMISSION_REJECTED", "QUALIFICATION",
    "POLICY_ARTIFACT_ISSUED", "EXECUTION_COMPLETED", "EXECUTION_FAILED",
    "EFFECT_ATTESTED",
)

# §4.7.1 lists five; §4.8 requires the sixth and NT-007 tests it. The gap between the
# two is recorded in the v1.0.1 defect register.
BLOCK_REASONS = (
    "ECC_EXPIRED", "ECC_INTEGRITY_INVALID", "ECC_NOT_FOUND", "ECC_INVARIANT_STALE",
    "ECC_ALREADY_REDEEMED", "AUTHORIZATION_ALREADY_REDEEMED",
)


class AuditStore(object):
    """C5. Durable, append-only, hash-chained.

    `path` puts the write-ahead log on disk with a real fsync per event; the default
    keeps it in memory for tests. `replicate_to` attaches a central store so a scenario
    can exercise the asynchronous half of Appendix R.
    """

    def __init__(self, path=None, signer=None, replicate_to=None, max_lag=64):
        self.signer = signer or LocalSigner()
        self.wal = WriteAheadLog(self.signer, path=path)
        self.central = replicate_to if replicate_to is not None else CentralStore(self.signer)
        self.replicator = Replicator(self.wal, self.central, max_lag=max_lag)

    # ------------------------------------------------------------------ record
    @property
    def events(self):
        return self.wal.records

    def emit(self, etype, emitter_id, subject_id, **fields):
        """Record one governance event and durably commit it.

        Returns after the local durable write, so a caller may treat the return as the
        I6 gate: "recorded in C5 synchronously with its occurrence and before the next
        governed action is admitted for evaluation" (§4.7).
        """
        if etype not in EVENT_TYPES:
            raise ValueError("%r is not a v1.0.1 event.type (§4.7.1)" % etype)
        br = fields.get("event.block_reason")
        if br is not None and br not in BLOCK_REASONS:
            raise ValueError("%r is not a v1.0.1 event.block_reason (§4.7.1, §4.8)" % br)

        event = {
            "event.id": "evt-" + uuid.uuid4().hex[:16],
            "event.type": etype,
            "event.timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event.subject_id": subject_id,
            "event.emitter_id": emitter_id,
        }
        event.update(fields)
        return self.wal.append(event)

    # --------------------------------------------------------------- integrity
    def verify_chain(self):
        """Recompute the chain and the signatures.

        On its own this establishes only that the events present were not altered or
        reordered -- not that they describe a coherent sequence of decisions. That is
        what `verify_decisions` is for, and keeping the two apart is the point: a log
        can be perfectly intact and still record an impossible history.
        """
        return self.wal.verify()

    # ------------------------------------------------------------- correlation
    def verify_decisions(self):
        """Causal correlation over the record (Appendix G.2.4). Returns (ok, message).

        In one pass:
          1. every ECC_COMPILED cites a permit event that precedes it;
          2. at most one ECC_COMPILED per permit event;
          3. every EXECUTION_AUTHORIZED cites an ECC compiled earlier;
          4. at most one EXECUTION_AUTHORIZED per ecc.id  (§4.8 single-use);
          5. at most one EXECUTION_AUTHORIZED per auth_id (§4.8 governed exception);
          6. the executing subject is the subject the ECC was compiled for;
          7. every effect-attestation event cites an ECC that was authorized.

        Checks 4 and 5 are the ones that catch a redemption race: a registry that
        granted twice leaves two EXECUTION_AUTHORIZED events behind, and no amount of
        chain integrity hides that.
        """
        permits = {}
        compiled = {}
        permit_compiled = {}
        executed_ecc = {}
        executed_auth = {}

        for ev in self.events:
            t = ev["event.type"]

            if t == "PERMIT":
                permits[ev["event.id"]] = ev

            elif t == "ECC_COMPILED":
                pid = ev.get("event.permit_event_id")
                if pid is None:
                    return False, "ECC_COMPILED %s cites no permit event" % ev["event.id"]
                if pid not in permits:
                    return False, ("ECC_COMPILED %s cites permit %s, which does not "
                                   "precede it" % (ev["event.id"], pid))
                if pid in permit_compiled:
                    return False, ("permit %s produced more than one ECC: %s and %s"
                                   % (pid, permit_compiled[pid], ev.get("event.ecc_id")))
                permit_compiled[pid] = ev.get("event.ecc_id")
                compiled[ev["event.ecc_id"]] = ev

            elif t == "EXECUTION_AUTHORIZED":
                eid = ev.get("event.ecc_id")
                if eid not in compiled:
                    return False, ("EXECUTION_AUTHORIZED %s cites ECC %s, which was never "
                                   "compiled in this record" % (ev["event.id"], eid))
                if eid in executed_ecc:
                    return False, "ECC %s was authorized more than once" % eid
                executed_ecc[eid] = ev

                if compiled[eid]["event.subject_id"] != ev["event.subject_id"]:
                    return False, ("ECC %s was compiled for %s but executed as %s"
                                   % (eid, compiled[eid]["event.subject_id"],
                                      ev["event.subject_id"]))

                aid = ev.get("event.auth_id")
                if aid is not None:
                    if aid in executed_auth:
                        return False, ("authorization %s backed more than one execution "
                                       "(%s and %s)"
                                       % (aid, executed_auth[aid]["event.ecc_id"], eid))
                    executed_auth[aid] = ev

            elif t in ("EXECUTION_COMPLETED", "EXECUTION_FAILED", "EFFECT_ATTESTED"):
                eid = ev.get("event.ecc_id")
                if eid not in executed_ecc:
                    return False, ("%s %s attests an effect for ECC %s, which was never "
                                   "authorized" % (t, ev["event.id"], eid))

        return True, ("decisions correlated: %d permits, %d ECCs, %d executions, "
                      "%d governed exceptions, each at most once"
                      % (len(permits), len(compiled), len(executed_ecc), len(executed_auth)))

    def verify(self):
        """Integrity and correlation. Returns (ok, message)."""
        ok, msg = self.verify_chain()
        if not ok:
            return False, msg
        ok2, msg2 = self.verify_decisions()
        if not ok2:
            return False, msg2
        return True, "%s; %s" % (msg, msg2)

    # ------------------------------------------------------------ replication
    def replicate(self):
        """Appendix R steps 7-9. Never called on the admission path."""
        return self.replicator.flush()

    def reconcile(self):
        """R.4 invariant 7: local WAL and central store must agree."""
        return self.replicator.reconcile()

    def dump(self, path):
        import json
        with open(path, "w", encoding="utf-8") as fh:
            for ev in self.events:
                fh.write(json.dumps(ev, sort_keys=True) + "\n")
