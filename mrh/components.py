"""Mock C1-C7 components. Deliberately minimal: enough to demonstrate the enforcement
properties (structural boundary, single-use signed commitments, governed exception),
not to be a real deployment.

September 2026 — this module was corrected after an independent audit reproduced three
defects (H-01, H-02, H-03; see spec/known-defects-harness.md in the CROA repository).
The corrections are marked FIX H-0n below.
"""
import hashlib
import hmac
import json
import threading
import time
import uuid

_CC_KEY = b"CROA-MRH-CC-DEMO-KEY"


def _canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


class AuthorizationSpent(Exception):
    """Raised when a governed-exception authorization is presented for compilation after
    it has already been reserved. FIX H-01: this is the fail-deny that stops one
    single-use authorization from backing more than one commitment."""


class CommitmentMismatch(Exception):
    """Raised when what is presented at the boundary is not what the commitment authorizes."""


# --- C1: Policy Authority -------------------------------------------------
class PolicyAuthority:
    """Holds registered invariants and issues signed, time-bounded authorization
    artifacts for governed exceptions. The agent can never issue these."""

    def __init__(self, approved_export_targets):
        self.approved_export_targets = set(approved_export_targets)
        self.redeemed_auths = set()   # authorizations already spent (single-use)
        # FIX H-01. Part II §4.8 requires redemption to be a single atomic linearizable
        # compare-and-swap. The previous code read `redeemed_auths` in
        # authorization_covers() and wrote it later, from the harness, only after C6 had
        # admitted — a check-then-act. Every commitment compiled in that window was
        # admissible. This lock makes reserve_authorization() the one place where the
        # test and the set happen together. In a real deployment this is not a local
        # lock but one shared authority: a conditional write, a compare-and-swap, or a
        # transaction, visible to every C6 and C7 instance.
        self._lock = threading.Lock()

    def violated_invariants(self, action):
        v = []
        if (action["action_class"] == "data.export"
                and action["target"] not in self.approved_export_targets):
            v.append("I-EXPORT-001")   # data.export target must be an approved destination
        return v

    def issue_authorization(self, action, now, ttl=60):
        auth = {
            "auth_id": "auth-" + uuid.uuid4().hex[:12],
            "action_fingerprint": hashlib.sha256(_canon(action).encode()).hexdigest(),
            "expiry": now + ttl,
        }
        auth["signature"] = hmac.new(_CC_KEY, _canon(auth).encode(), hashlib.sha256).hexdigest()
        return auth

    def _auth_valid_for(self, auth, action, now):
        """Signature, expiry and action-binding checks. Says nothing about whether the
        authorization is still unspent — that question can only be answered by the
        atomic reserve below, because any answer given here is stale by the time the
        caller acts on it."""
        if auth is None:
            return False
        unsigned = {k: v for k, v in auth.items() if k != "signature"}
        expected = hmac.new(_CC_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, auth["signature"]):
            return False
        if now > auth["expiry"]:
            return False
        return hmac.compare_digest(
            auth["action_fingerprint"],
            hashlib.sha256(_canon(action).encode()).hexdigest(),
        )

    def authorization_covers(self, auth, action, now):
        """Advisory read, used by C2 to reach a decision. A PERMIT_WITH_AUTHORIZATION
        decision is *not* a reservation: the authorization is only spent when C7
        successfully reserves it. See reserve_authorization()."""
        if not self._auth_valid_for(auth, action, now):
            return False
        return auth["auth_id"] not in self.redeemed_auths

    def reserve_authorization(self, auth, action, now):
        """FIX H-01 — atomic test-and-set. Returns the auth_id on success; raises
        AuthorizationSpent if this authorization has already backed a commitment.
        This is the only method that may spend an authorization."""
        if not self._auth_valid_for(auth, action, now):
            raise AuthorizationSpent("authorization invalid, expired, or not bound to this action")
        with self._lock:
            if auth["auth_id"] in self.redeemed_auths:
                raise AuthorizationSpent(f"{auth['auth_id']} already spent")
            self.redeemed_auths.add(auth["auth_id"])
            return auth["auth_id"]

    def redeem_authorization(self, auth_id):
        """Retained for API compatibility. Reservation now happens at compilation, so
        this is idempotent and no longer the point at which an authorization is spent."""
        with self._lock:
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
    """Compiles a permitted action into the single artifact allowed across the boundary."""

    def __init__(self, c1):
        self.c1 = c1

    def compile(self, action, now, permit_event_id, authorization=None, ttl=300):
        """FIX H-01: reserves the authorization atomically *before* producing a
        commitment, so a spent authorization yields no commitment at all.
        FIX H-03: cc.id is the SHA-256 of the commitment's canonical content, with no
        random component. The content includes permit_event_id, which is unique per
        decision, so two legitimate decisions over the same action still yield distinct
        identifiers while the identifier remains a true content address.
        """
        auth_ref = None
        if authorization is not None:
            # Raises AuthorizationSpent — fail-deny, no commitment produced.
            auth_ref = self.c1.reserve_authorization(authorization, action, now)

        content = {
            "action": action,
            "subject": action["subject_id"],
            "permit_event_id": permit_event_id,
            "issued_at": now,
            "expiry": now + ttl,
            "single_use": True,
        }
        if auth_ref is not None:
            content["auth_ref"] = auth_ref

        cc = dict(content)
        cc["cc.id"] = "cc-" + hashlib.sha256(_canon(content).encode()).hexdigest()
        cc["signature"] = hmac.new(
            _CC_KEY, _canon({k: v for k, v in cc.items() if k != "signature"}).encode(),
            hashlib.sha256,
        ).hexdigest()
        return cc


# --- C6: Execution Firewall ----------------------------------------------
class ExecutionFirewall:
    """The execution boundary: admits only a valid, unexpired, unredeemed, correctly
    signed Compiled Commitment, presented by the subject it was compiled for, for the
    operation it authorizes."""

    def __init__(self):
        self.redeemed = set()
        self.redeemed_auths = set()
        # FIX H-01/H-02: redemption is one atomic section, not a check followed by a set.
        self._lock = threading.Lock()

    def _sig_ok(self, cc):
        unsigned = {k: v for k, v in cc.items() if k != "signature"}
        expected = hmac.new(_CC_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, cc.get("signature", ""))

    def _id_ok(self, cc):
        """FIX H-03: recompute the content address and compare. A commitment whose
        identifier is not the hash of its own content is refused."""
        content = {k: v for k, v in cc.items() if k not in ("cc.id", "signature")}
        return hmac.compare_digest(
            cc.get("cc.id", ""),
            "cc-" + hashlib.sha256(_canon(content).encode()).hexdigest(),
        )

    def redeem(self, cc, now, subject_id, operation):
        """FIX H-02: the boundary now requires the authenticated subject and the concrete
        operation, and compares both against the signed commitment. `subject_id` and
        `operation` are mandatory — the unsafe call is no longer expressible.
        """
        if cc is None:
            return "BLOCKED", "CC_NOT_FOUND"
        if not self._sig_ok(cc):
            return "BLOCKED", "CC_SIGNATURE_INVALID"
        if not self._id_ok(cc):
            return "BLOCKED", "CC_ID_NOT_CONTENT_ADDRESSED"
        if now > cc["expiry"]:
            return "BLOCKED", "CC_EXPIRED"
        if subject_id != cc["subject"]:
            return "BLOCKED", "CC_SUBJECT_MISMATCH"
        if _canon(operation) != _canon(cc["action"]):
            return "BLOCKED", "CC_OPERATION_MISMATCH"

        with self._lock:
            if cc["cc.id"] in self.redeemed:
                return "BLOCKED", "CC_ALREADY_REDEEMED"
            auth_ref = cc.get("auth_ref")
            if auth_ref is not None and auth_ref in self.redeemed_auths:
                return "BLOCKED", "AUTHORIZATION_ALREADY_REDEEMED"
            self.redeemed.add(cc["cc.id"])
            if auth_ref is not None:
                self.redeemed_auths.add(auth_ref)
        return "AUTHORIZED", None
