"""Mock C1-C7 components. Deliberately minimal: enough to demonstrate the enforcement
properties (structural boundary, single-use signed commitments, governed exception),
not to be a real deployment."""
import hashlib, hmac, json, time, uuid

_CC_KEY = b"CROA-MRH-CC-DEMO-KEY"

def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"))

# --- C1: Policy Authority -------------------------------------------------
class PolicyAuthority:
    """Holds registered invariants and issues signed, time-bounded authorization
    artifacts for governed exceptions. The agent can never issue these."""
    def __init__(self, approved_export_targets):
        self.approved_export_targets = set(approved_export_targets)
        self.redeemed_auths = set()   # governed-exception authorizations already spent (single-use)

    def violated_invariants(self, action):
        v = []
        if action["action_class"] == "data.export" and action["target"] not in self.approved_export_targets:
            v.append("I-EXPORT-001")   # data.export target must be an approved export destination
        return v

    def issue_authorization(self, action, now, ttl=60):
        auth = {"auth_id": "auth-" + uuid.uuid4().hex[:12],
                "action_fingerprint": hashlib.sha256(_canon(action).encode()).hexdigest(),
                "expiry": now + ttl}
        auth["signature"] = hmac.new(_CC_KEY, _canon(auth).encode(), hashlib.sha256).hexdigest()
        return auth

    def authorization_covers(self, auth, action, now):
        if auth is None: return False
        unsigned = {k: v for k, v in auth.items() if k != "signature"}
        if hmac.new(_CC_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest() != auth["signature"]:
            return False
        if now > auth["expiry"]: return False
        if auth["auth_id"] in self.redeemed_auths: return False   # single-use: already spent, even within TTL
        return auth["action_fingerprint"] == hashlib.sha256(_canon(action).encode()).hexdigest()

    def redeem_authorization(self, auth_id):
        """Mark a governed-exception authorization as spent. After this it no longer covers
        any action (single-use), even before its expiry."""
        self.redeemed_auths.add(auth_id)

# --- C3: Path Resolver ----------------------------------------------------
class PathResolver:
    def __init__(self, golden_record):
        self.golden_record = set(golden_record)
    def resolve(self, target):
        return target in self.golden_record

# --- C2: Execution Governor ----------------------------------------------
class ExecutionGovernor:
    def __init__(self, c1):
        self.c1 = c1
    def evaluate(self, action, authorization, now):
        violations = self.c1.violated_invariants(action)
        if not violations:
            return "PERMIT", "no registered invariant violated"
        if self.c1.authorization_covers(authorization, action, now):
            return "PERMIT_WITH_AUTHORIZATION", "covered by " + authorization["auth_id"]
        return "DENY", "violates " + ",".join(violations)

# --- C7: Contract Compiler ------------------------------------------------
class ContractCompiler:
    def compile(self, action, now, authorization=None, ttl=300):
        cc = {"cc.id": "cc-" + hashlib.sha256((_canon(action) + uuid.uuid4().hex).encode()).hexdigest()[:16],
              "action": action, "expiry": now + ttl, "single_use": True}
        if authorization is not None:
            cc["auth_ref"] = authorization["auth_id"]   # CC carries the authorization's reference (white paper 3.7)
        cc["signature"] = hmac.new(_CC_KEY, _canon({k: v for k, v in cc.items()}).encode(), hashlib.sha256).hexdigest()
        return cc

# --- C6: Execution Firewall ----------------------------------------------
class ExecutionFirewall:
    """The execution boundary: admits only valid, unexpired, unredeemed, correctly
    signed Compiled Commitments. Everything else is blocked."""
    def __init__(self):
        self.redeemed = set()
    def _sig_ok(self, cc):
        unsigned = {k: v for k, v in cc.items() if k != "signature"}
        return hmac.new(_CC_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest() == cc["signature"]
    def redeem(self, cc, now):
        if cc is None:
            return "BLOCKED", "CC_NOT_FOUND"
        if not self._sig_ok(cc):
            return "BLOCKED", "CC_SIGNATURE_INVALID"
        if now > cc["expiry"]:
            return "BLOCKED", "CC_EXPIRED"
        if cc["cc.id"] in self.redeemed:
            return "BLOCKED", "CC_ALREADY_REDEEMED"
        self.redeemed.add(cc["cc.id"])
        return "AUTHORIZED", None
