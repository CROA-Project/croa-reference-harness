"""C1-C7. Deliberately minimal: enough to demonstrate the enforcement properties --
structural boundary, single-use signed contracts, governed exception -- not to be a
real deployment.

History. In September 2026 an independent audit reproduced three defects (H-01, H-02,
H-03; see spec/known-defects-harness.md). Their fixes are marked FIX H-0n below and
are preserved.

v1.0.1 rework. The H-01 fix made C7 spend the authorization at compile time, using a
lock inside C1. That closed the reproduced bypass, but it is not where §4.8 puts
redemption, and it left a second hole the audit did not reach: `ExecutionFirewall`
carried its own `redeemed` and `redeemed_auths` sets, so two firewall instances each
admitted the same ECC once. §4.8 calls a per-instance redemption record non-conformant
wherever more than one instance can admit operations for the same governed system.

So redemption moved to where the specification puts it:

  * C7 *binds* `ecc.auth_ref` and `ecc.exception_scope` into the contract. It no longer
    spends anything. Two ECCs may legitimately be compiled against one authorization --
    §4.8 anticipates exactly that and requires C6 to refuse the second at admission.
  * C6 holds no redemption state. It performs one atomic claim over {ecc.id, auth_ref}
    against a shared registry (`mrh/redemption.py`), which is what §4.8 asks for and
    what makes NT-007 step 4 -- two concurrent presentations, at most one execution --
    pass with two firewall instances rather than one.

The property the H-01 fix protected is unchanged and still tested: one single-use
authorization backs at most one admitted execution. It is now enforced at the boundary
instead of at the compiler, which is both the specified place and the only place that
holds when there is more than one compiler.
"""
import hashlib
import hmac
import json
import uuid

_ECC_KEY = b"CROA-MRH-ECC-DEMO-KEY"


def _canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


class CommitmentMismatch(Exception):
    """What is presented at the boundary is not what the contract authorizes."""


class AuthorizationInvalid(Exception):
    """The authorization is unsigned, expired, or not bound to this action.

    Distinct from an authorization that is merely *spent*: spent is a fact only the
    redemption registry can establish, and only at admission.
    """


# --- C1: Policy Authority -------------------------------------------------
class PolicyAuthority(object):
    """Holds registered invariants and issues signed, time-bounded authorization
    artifacts for governed exceptions (§4.3.1). The agent can never issue these."""

    def __init__(self, approved_export_targets, invariant_set_version="inv-2026-09-01",
                 policy_artifact_id="pol-core-data-protection@1.4.0"):
        self.approved_export_targets = set(approved_export_targets)
        self.invariant_set_version = invariant_set_version
        # §4.7.1 requires every decision event to name the C1 artifact it was issued
        # under, so a decision can be re-derived years later against the policy that
        # actually applied to it (I3).
        self.policy_artifact_id = policy_artifact_id

    def violated_invariants(self, action):
        v = []
        if (action["action_class"] == "data.export"
                and action["target"] not in self.approved_export_targets):
            v.append("I-EXPORT-001")   # data.export target must be an approved destination
        return v

    def issue_authorization(self, action, now, ttl=60, waived=("I-EXPORT-001",)):
        """Issue a single-use authorization bounded to one action class and target.

        `exception_scope` is the §4.3.1 bounded scope that C7 copies unchanged into the
        ECC: the invariants waived, the single action class, the target constraint and
        the validity window. C6 enforces it at the boundary, which is what stops the
        scope-widening half of NT-007.
        """
        auth = {
            "auth_id": "auth-" + uuid.uuid4().hex[:12],
            "action_fingerprint": hashlib.sha256(_canon(action).encode()).hexdigest(),
            "expiry": now + ttl,
            "redemption_policy": "single-use",
            "exception_scope": {
                "waived_invariants": list(waived),
                "action_class": action["action_class"],
                "target_constraints": [action["target"]],
                "expires_at": now + ttl,
            },
        }
        auth["signature"] = hmac.new(_ECC_KEY, _canon(auth).encode(), hashlib.sha256).hexdigest()
        return auth

    def authorization_valid_for(self, auth, action, now):
        """Signature, expiry and action binding.

        Says nothing about whether the authorization is still unspent. That question
        has no safe answer here: any answer is stale by the time the caller acts on it,
        which is the time-of-check-to-time-of-use race §4.8 forbids. Only the atomic
        claim at C6 can answer it.
        """
        if auth is None:
            return False
        unsigned = dict((k, v) for k, v in auth.items() if k != "signature")
        expected = hmac.new(_ECC_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, auth.get("signature", "")):
            return False
        if now > auth["expiry"]:
            return False
        return hmac.compare_digest(
            auth["action_fingerprint"],
            hashlib.sha256(_canon(action).encode()).hexdigest(),
        )


# --- C3: Path Resolver ----------------------------------------------------
class PathResolver(object):
    """Grounds a request against the Federated Context Registry (§4.5.2).

    `available=False` models the registry being unreachable or its snapshot too old.
    §4.5 is explicit that this is fail-closed and not merely a resolution failure: "a
    grounding that cannot be performed is treated as a grounding that failed", and the
    pipeline MUST NOT fall through to C2.
    """

    def __init__(self, context_registry, available=True):
        self.context_registry = set(context_registry)
        self.available = available

    def resolve(self, target):
        if not self.available:
            return False
        return target in self.context_registry


# --- C2: Execution Governor ----------------------------------------------
class ExecutionGovernor(object):
    """Deterministic permit-or-deny evaluation (§4.4.2)."""

    def __init__(self, c1, registry=None):
        self.c1 = c1
        # Advisory only: lets C2 deny early on an authorization it can already see is
        # spent, which NT-007 step 2 accepts as an alternative to a block at C6. It is
        # never the guarantee -- the guarantee is the atomic claim at the boundary.
        self.registry = registry

    def evaluate(self, action, authorization, now):
        """Returns (decision, reason, invariant_state).

        `invariant_state` is the §4.7.1 field: on a DENY it names the violated
        invariants, on a PERMIT it attests that none was violated. Returning it from
        the evaluator rather than reconstructing it at the log is deliberate -- an
        attestation assembled by the recorder is an attestation about the recorder.
        """
        violations = self.c1.violated_invariants(action)
        if not violations:
            return ("PERMIT", "no registered invariant violated",
                    {"violated": [], "attestation": "no registered invariant violated"})
        if not self.c1.authorization_valid_for(authorization, action, now):
            return ("DENY", "violates " + ",".join(violations), {"violated": violations})
        if self.registry is not None and self.registry.is_spent(authorization["auth_id"]):
            return ("DENY", "authorization %s already redeemed" % authorization["auth_id"],
                    {"violated": violations})
        return ("PERMIT_WITH_AUTHORIZATION", "covered by " + authorization["auth_id"],
                {"violated": violations,
                 "waived_under": authorization["auth_id"],
                 "attestation": "violation waived by a valid C1 authorization"})


# --- C7: Contract Compiler ------------------------------------------------
class ContractCompiler(object):
    """Compiles a permitted action into the single artifact allowed across TB-3."""

    def __init__(self, c1):
        self.c1 = c1

    def compile(self, action, now, permit_event_id, authorization=None, ttl=300,
                additional_scope=None):
        """Produce an ECC (§4.4.1).

        FIX H-03: `ecc.id` is the SHA-256 of the contract's canonical content with no
        random component. The content includes `ecc.permit_event_id`, unique per
        decision, so two legitimate decisions over the same action still yield distinct
        identifiers while the identifier remains a true content address.

        v1.0.1: on a PERMIT_WITH_AUTHORIZATION decision this binds `ecc.auth_ref` and
        copies `ecc.exception_scope` in unchanged (§4.3.1, §4.4.3). It does not spend
        the authorization -- C6 does, atomically, at admission.

        `additional_scope` lets a permit cover more of an action class than the
        exception waives. The two scopes are independent by design: §4.3.1 says the
        bounded exception scope "does not widen ecc.authorization_scope", and the
        converse holds too -- a broader permit does not widen the waiver. C6 enforces
        both, so an operation inside the permit but outside the waiver is refused.
        """
        content = {
            "ecc.action": action,
            "ecc.subject": action["subject_id"],
            "ecc.session_id": action.get("session_id", "sess-" + action["subject_id"]),
            "ecc.permit_event_id": permit_event_id,
            "ecc.compiled_at": now,
            "ecc.expires_at": now + ttl,
            "ecc.invariant_set_version": self.c1.invariant_set_version,
            "ecc.authorization_scope": [{
                "target": action["target"],
                "action_type": action["action_class"],
            }] + list(additional_scope or []),
            "ecc.decision_basis": "PERMIT" if authorization is None else "PERMIT_WITH_AUTHORIZATION",
        }
        if authorization is not None:
            if not self.c1.authorization_valid_for(authorization, action, now):
                raise AuthorizationInvalid("authorization invalid, expired, or not bound to this action")
            content["ecc.auth_ref"] = authorization["auth_id"]
            content["ecc.exception_scope"] = authorization["exception_scope"]

        ecc = dict(content)
        ecc["ecc.id"] = "ecc-" + hashlib.sha256(_canon(content).encode()).hexdigest()
        ecc["ecc.signature"] = hmac.new(
            _ECC_KEY,
            _canon(dict((k, v) for k, v in ecc.items() if k != "ecc.signature")).encode(),
            hashlib.sha256,
        ).hexdigest()
        return ecc


# --- C6: Execution Firewall ----------------------------------------------
class ExecutionFirewall(object):
    """The execution boundary (§4.8).

    Admits only a valid, unexpired, unredeemed, correctly signed ECC, presented by the
    subject it was compiled for, for an operation inside the scope it authorizes.

    Holds **no** redemption state. Every instance sharing a governance domain is
    constructed with the same `RedemptionRegistry`, which is what §4.8 means by "one
    authoritative redemption registry": a per-instance record is non-conformant
    wherever more than one instance can admit operations for the same system.
    """

    def __init__(self, registry, instance_id="c6-1"):
        self.registry = registry
        self.instance_id = instance_id

    # ------------------------------------------------------------- validation
    def _signature_ok(self, ecc):
        unsigned = dict((k, v) for k, v in ecc.items() if k != "ecc.signature")
        expected = hmac.new(_ECC_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, ecc.get("ecc.signature", ""))

    def _content_address_ok(self, ecc):
        """FIX H-03: recompute the content address. A contract whose identifier is not
        the hash of its own content is refused."""
        content = dict((k, v) for k, v in ecc.items() if k not in ("ecc.id", "ecc.signature"))
        return hmac.compare_digest(
            ecc.get("ecc.id", ""),
            "ecc-" + hashlib.sha256(_canon(content).encode()).hexdigest(),
        )

    def _in_authorization_scope(self, ecc, operation):
        for entry in ecc.get("ecc.authorization_scope", []):
            if (entry.get("target") == operation.get("target")
                    and entry.get("action_type") == operation.get("action_class")):
                return True
        return False

    def _in_exception_scope(self, ecc, operation):
        """§4.3.1: C6 MUST enforce that the executed operation lies within
        `ecc.exception_scope`. This is the scope-widening half of NT-007: an ECC
        compiled for `billing` must not admit an export to `analytics`."""
        scope = ecc.get("ecc.exception_scope")
        if scope is None:
            return True
        if operation.get("action_class") != scope.get("action_class"):
            return False
        targets = scope.get("target_constraints")
        if targets is not None and operation.get("target") not in targets:
            return False
        return True

    # -------------------------------------------------------------- admission
    def redeem(self, ecc, now, subject_id, operation, invariant_set_version=None):
        """Validate, then claim atomically. Returns (status, block_reason, detail).

        FIX H-02: `subject_id` is the *authenticated* identity of whoever is presenting
        and `operation` is what they are actually asking to perform. Both are mandatory
        and both are compared against the signed contract; the unsafe call is not
        expressible.

        Ordering matters and is the whole point of §4.8. Every static check runs first,
        because a claim is irreversible and an ECC refused on expiry must not consume
        its own single use. The claim is then one indivisible operation over both keys.
        Nothing is released to the governed system before it succeeds.
        """
        if ecc is None:
            return "BLOCKED", "ECC_NOT_FOUND", None
        if not self._signature_ok(ecc):
            return "BLOCKED", "ECC_INTEGRITY_INVALID", "SIGNATURE_INVALID"
        if not self._content_address_ok(ecc):
            return "BLOCKED", "ECC_INTEGRITY_INVALID", "ID_NOT_CONTENT_ADDRESSED"
        if now > ecc["ecc.expires_at"]:
            return "BLOCKED", "ECC_EXPIRED", None
        if subject_id != ecc["ecc.subject"]:
            return "BLOCKED", "ECC_INTEGRITY_INVALID", "SUBJECT_MISMATCH"
        if not self._in_authorization_scope(ecc, operation):
            # §4.8 requires every operation in the request to lie within
            # ecc.authorization_scope but names no block reason for the failure. The
            # §4.7.1 enumeration is closed and has none that fits, so the nearest true
            # one is used and the precise cause goes in a non-normative detail field.
            # Recorded in the v1.0.1 defect register as an enumeration gap.
            return "BLOCKED", "ECC_INTEGRITY_INVALID", "OPERATION_OUTSIDE_AUTHORIZATION_SCOPE"
        if not self._in_exception_scope(ecc, operation):
            return "BLOCKED", "ECC_INTEGRITY_INVALID", "OPERATION_OUTSIDE_EXCEPTION_SCOPE"
        if (invariant_set_version is not None
                and ecc.get("ecc.invariant_set_version") != invariant_set_version):
            # §4.8: an invariant registered or upgraded since compilation may prohibit
            # an operation in scope; the ECC must be recompiled.
            return "BLOCKED", "ECC_INVARIANT_STALE", None

        keys = {"ecc": ecc["ecc.id"]}
        auth_ref = ecc.get("ecc.auth_ref")
        if auth_ref is not None:
            keys["auth"] = auth_ref                 # same claim, not a second one

        result = self.registry.claim(keys)
        if not result.granted:
            reason = ("ECC_ALREADY_REDEEMED" if result.conflict == "ecc"
                      else "AUTHORIZATION_ALREADY_REDEEMED")
            return "BLOCKED", reason, result.conflict_key
        return "AUTHORIZED", None, None
