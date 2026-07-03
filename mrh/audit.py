"""C5 — Audit & Provenance Store: append-only, hash-chained, signed governance events.
Signatures use HMAC with a DEMO key — this is a demonstrator, not real key management."""
import hashlib, hmac, json, uuid, datetime

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
        ev["event.emitter_signature"] = hmac.new(_DEMO_KEY, _canon(ev).encode(), hashlib.sha256).hexdigest()
        self.events.append(ev)
        self._prev = _sha(_canon(ev))
        return ev

    def verify(self):
        """Recompute the chain and signatures. Returns (ok, message)."""
        prev = GENESIS
        for ev in self.events:
            if ev["event.chain_hash"] != prev:
                return False, f"chain break at {ev['event.id']}"
            unsigned = {k: v for k, v in ev.items() if k != "event.emitter_signature"}
            sig = hmac.new(_DEMO_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest()
            if sig != ev["event.emitter_signature"]:
                return False, f"bad signature at {ev['event.id']}"
            prev = _sha(_canon(ev))
        return True, f"chain verified: {len(self.events)} events, unbroken"

    def dump(self, path):
        with open(path, "w") as f:
            for ev in self.events:
                f.write(json.dumps(ev) + "\n")
