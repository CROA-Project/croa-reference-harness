"""C5 — Audit & Provenance Store: append-only, hash-chained, signed governance events.
Signatures use HMAC with a DEMO key — this is a demonstrator, not real key management.

September 2026 — verify() was corrected after an independent audit (H-04). It previously
recomputed the chain and each signature and did nothing else, so a log containing two
authorized executions from one single-use authorization verified as valid. It now performs
the causal correlation Appendix G.2.4 requires.
"""
import hashlib
import hmac
import json
import uuid
import datetime

_DEMO_KEY = b"CROA-MRH-DEMO-KEY-not-for-production"
GENESIS = "0" * 64


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


class AuditStore:
    """Append-only, tamper-evident C5 event log."""

    def __init__(self):
        self.events = []
        self._prev = GENESIS

    def emit(self, etype, emitter_id, subject_id, **fields):
        ev = {
            "event.id": "evt-" + uuid.uuid4().hex[:16],
            "event.type": etype,
            "event.timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event.subject_id": subject_id,
            "event.emitter_id": emitter_id,
            "event.chain_hash": self._prev,
        }
        ev.update(fields)
        # sign over all fields except the signature itself
        ev["event.emitter_signature"] = hmac.new(
            _DEMO_KEY, _canon(ev).encode(), hashlib.sha256
        ).hexdigest()
        self.events.append(ev)
        self._prev = _sha(_canon(ev))
        return ev

    # ------------------------------------------------------------------ integrity
    def verify_chain(self):
        """Recompute the chain and signatures. Returns (ok, message).

        This is what verify() used to be, and on its own it establishes only that the
        events present were not altered or reordered — not that they describe a coherent
        sequence of decisions.
        """
        prev = GENESIS
        for ev in self.events:
            if ev["event.chain_hash"] != prev:
                return False, f"chain break at {ev['event.id']}"
            unsigned = {k: v for k, v in ev.items() if k != "event.emitter_signature"}
            sig = hmac.new(_DEMO_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, ev["event.emitter_signature"]):
                return False, f"bad signature at {ev['event.id']}"
            prev = _sha(_canon(ev))
        return True, f"chain verified: {len(self.events)} events, unbroken"

    # --------------------------------------------------------------- correlation
    def verify_decisions(self):
        """FIX H-04 — Appendix G.2.4 correlation. Returns (ok, message).

        Checks, in one pass:
          1. every CC_COMPILED cites a permit_event_id that is an earlier PERMIT;
          2. at most one CC_COMPILED per permit event;
          3. every EXECUTION_AUTHORIZED cites a cc_id compiled earlier;
          4. **at most one EXECUTION_AUTHORIZED per cc_id**;
          5. **at most one EXECUTION_AUTHORIZED per auth_id** — the check that catches
             H-01, where one single-use authorization backed two admitted executions;
          6. the subject on an EXECUTION_AUTHORIZED matches the subject on the
             CC_COMPILED it derives from — the check that catches H-02.
        """
        permits = {}          # event.id -> PERMIT event
        compiled = {}         # cc_id -> CC_COMPILED event
        permit_compiled = {}  # permit_event_id -> cc_id
        executed_cc = {}      # cc_id -> EXECUTION_AUTHORIZED event
        executed_auth = {}    # auth_id -> EXECUTION_AUTHORIZED event

        for ev in self.events:
            t = ev["event.type"]

            if t == "PERMIT":
                permits[ev["event.id"]] = ev

            elif t == "CC_COMPILED":
                pid = ev.get("event.permit_event_id")
                if pid is None:
                    return False, f"CC_COMPILED {ev['event.id']} cites no permit event"
                if pid not in permits:
                    return False, (f"CC_COMPILED {ev['event.id']} cites permit {pid}, "
                                   "which does not precede it")
                if pid in permit_compiled:
                    return False, (f"permit {pid} produced more than one commitment: "
                                   f"{permit_compiled[pid]} and {ev.get('event.cc_id')}")
                permit_compiled[pid] = ev.get("event.cc_id")
                compiled[ev["event.cc_id"]] = ev

            elif t == "EXECUTION_AUTHORIZED":
                cid = ev.get("event.cc_id")
                if cid not in compiled:
                    return False, (f"EXECUTION_AUTHORIZED {ev['event.id']} cites commitment "
                                   f"{cid}, which was never compiled in this record")
                if cid in executed_cc:
                    return False, f"commitment {cid} was authorized more than once"
                executed_cc[cid] = ev

                if compiled[cid]["event.subject_id"] != ev["event.subject_id"]:
                    return False, (f"commitment {cid} was compiled for "
                                   f"{compiled[cid]['event.subject_id']} but executed as "
                                   f"{ev['event.subject_id']}")

                aid = ev.get("event.auth_id")
                if aid is not None:
                    if aid in executed_auth:
                        return False, (f"authorization {aid} backed more than one execution "
                                       f"({executed_auth[aid]['event.cc_id']} and {cid})")
                    executed_auth[aid] = ev

        return True, (f"decisions correlated: {len(permits)} permits, "
                      f"{len(compiled)} commitments, {len(executed_cc)} executions, "
                      f"{len(executed_auth)} governed exceptions, each at most once")

    def verify(self):
        """Full verification: integrity *and* causal correlation. Returns (ok, message)."""
        ok, msg = self.verify_chain()
        if not ok:
            return False, msg
        ok2, msg2 = self.verify_decisions()
        if not ok2:
            return False, msg2
        return True, f"{msg}; {msg2}"

    def dump(self, path):
        with open(path, "w") as f:
            for ev in self.events:
                f.write(json.dumps(ev) + "\n")
