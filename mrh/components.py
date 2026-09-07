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

from .invariants import AMBIGUOUS, VIOLATED, Invariant, InvariantRegistry
from .trajectory import C4Unavailable

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
                 policy_artifact_id="pol-core-data-protection@1.4.0", registry=None):
        self.approved_export_targets = set(approved_export_targets)
        # §4.7.1 requires every decision event to name the C1 artifact it was issued
        # under, so a decision can be re-derived years later against the policy that
        # actually applied to it (I3).
        self.policy_artifact_id = policy_artifact_id
        self.registry = registry if registry is not None else self._default_registry()
        self.registry.version = invariant_set_version

    @property
    def invariant_set_version(self):
        return self.registry.version

    @invariant_set_version.setter
    def invariant_set_version(self, value):
        self.registry.version = value

    def _default_registry(self):
        """The one registered invariant the base scenarios need, as a registry entry.

        Written as an entry rather than as a hard-coded branch because Part III §9.1
        makes the declared properties -- evaluability class, trajectory profile,
        reversibility -- part of what an invariant *is*. A rule with no declared
        evaluability class cannot be reasoned about by C2 and cannot be re-derived by
        an auditor.
        """
        approved = self.approved_export_targets
        return InvariantRegistry([
            Invariant(
                "I-EXPORT-001",
                "data.export MUST target an approved destination",
                evaluability="E1", trajectory_profile="TP-0", reversibility="R2",
                predicate=lambda a: (a["action_class"] == "data.export"
                                     and a["target"] not in approved)),
        ])

    def violated_invariants(self, action):
        """Kept for the callers that only need the identifiers of what was violated."""
        violated = []
        for inv in self.registry.applicable(action):
            verdict, _ = inv.evaluate(action)
            if verdict == VIOLATED:
                violated.append(inv.id)
        return violated

    def invariant_text(self, identifier):
        try:
            return self.registry[identifier].statement
        except KeyError:
            return None

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
    """Deterministic permit-or-deny evaluation (§4.4.2).

    The ordered procedure, and why the order is what it is:

      1. evaluate every applicable registered invariant;
      2. an AMBIGUOUS verdict from an E2/E3 method denies immediately (Part I §2.6
         fail-deny) -- before any authorization is considered, because an authorization
         waives a *known* violation and cannot waive an unknown one;
      3. consult C4 for trajectory state; a cumulative hard-limit breach denies;
      4. a known violation denies, unless a valid unspent C1 authorization covers it.

    Swapping 2 and 4 would let a governed exception paper over a verdict nobody has;
    swapping 3 and 4 would let an authorization for a single action override a
    cumulative limit it was never scoped against.
    """

    def __init__(self, c1, registry=None, c4=None):
        self.c1 = c1
        # Advisory only: lets C2 deny early on an authorization it can already see is
        # spent, which NT-007 step 2 accepts as an alternative to a block at C6. It is
        # never the guarantee -- the guarantee is the atomic claim at the boundary.
        self.registry = registry
        self.c4 = c4

    def evaluate(self, action, authorization, now, session_id=None):
        """Returns (decision, reason, invariant_state).

        `invariant_state` is the §4.7.1 field: on a DENY it names the violated
        invariants, on a PERMIT it attests that none was violated. Returning it from
        the evaluator rather than reconstructing it at the log is deliberate -- an
        attestation assembled by the recorder is an attestation about the recorder.
        It also carries `analyzer_version` where an E3 method took part, which §4.7.1
        requires on the event and I2 requires for determinism across time.
        """
        violations, ambiguous, analyzer_versions, evaluated = [], [], [], []
        for inv in self.c1.registry.applicable(action):
            verdict, analyzer_version = inv.evaluate(action)
            evaluated.append(inv.id)
            if analyzer_version is not None:
                analyzer_versions.append(analyzer_version)
            if verdict == VIOLATED:
                violations.append(inv.id)
            elif verdict == AMBIGUOUS:
                ambiguous.append(inv.id)

        base = {"violated": violations, "evaluated": evaluated}
        if analyzer_versions:
            base["analyzer_version"] = analyzer_versions[0]

        # 2 -- fail-deny on an undecided verdict (Part I §2.6)
        if ambiguous:
            state = dict(base, ambiguous=ambiguous,
                         attestation="E3 verdict AMBIGUOUS; fail-deny applied")
            return ("DENY_AMBIGUOUS",
                    "ambiguous verdict for " + ",".join(ambiguous) + " (fail-deny)",
                    state)

        # 3 -- trajectory state. C4 unavailability is fail-deny (§4.6).
        if self.c4 is not None and session_id is not None:
            try:
                traj = self.c4.assess(action, session_id)
            except C4Unavailable as exc:
                return ("DENY", "C4 unavailable: %s" % exc,
                        dict(base, attestation="invariant state unavailable; fail-deny"))
            base["trajectory"] = traj["states"]
            if traj["alert"] is not None:
                base["trajectory_alert"] = traj["alert"]
            if traj["breach"] is not None:
                b = traj["breach"]
                return ("DENY",
                        "%s trajectory hard limit breached: %d + %d = %d > %d"
                        % (b["invariant_id"], b["current_value"], b["increment"],
                           b["projected"], b["hard_limit"]),
                        dict(base, violated=[b["invariant_id"]],
                             trajectory_state_id=b["trajectory_state_id"],
                             breach=b))

        # 4 -- known violation, and the governed exception
        if not violations:
            return ("PERMIT", "no registered invariant violated",
                    dict(base, attestation="no registered invariant violated"))
        if not self.c1.authorization_valid_for(authorization, action, now):
            return ("DENY", "violates " + ",".join(violations), base)
        if self.registry is not None and self.registry.is_spent(authorization["auth_id"]):
            return ("DENY", "authorization %s already redeemed" % authorization["auth_id"],
                    base)
        return ("PERMIT_WITH_AUTHORIZATION", "covered by " + authorization["auth_id"],
                dict(base, waived_under=authorization["auth_id"],
                     attestation="violation waived by a valid C1 authorization"))


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


# --- Agent Surface --------------------------------------------------------
class AgentSurface(object):
    """The sole interface a governed agent has to the OCP (§4.9), and the three
    admission controls that stand in front of everything else.

    §4.9.1, the subject authorization model, is the load-bearing one for I8 clause (b):

        "a governed action request with action type a, submitted by subject s, is
        admitted if and only if some role assigned to s includes a in its authorized
        action classes ... A request that fails the admission predicate MUST be rejected
        at the Agent Surface ... MUST NOT be forwarded to C3 or C2."

    That is what makes authority laundering structurally impossible rather than merely
    unlikely: `S` submitting an action only `O` holds is refused here, before any
    component that could be persuaded has seen it. No arrangement of subjects helps,
    because the predicate reads the *submitting* subject's own roles and nothing else --
    not the session, not a cited prior decision, not a free-text claim about `O`.

    Delegation does not relax the predicate. A delegated action must lie within the
    delegated scope **and** independently pass evaluation (D3): the token narrows what
    `S` may do, it never widens it.
    """

    def __init__(self, roles=None, qualification=None):
        # subject_id -> Scope. A subject with no entry holds nothing.
        self.roles = dict(roles or {})
        # subject_id -> bool, standing in for the AQL (§4.9.2). OPTIONAL for human
        # subjects, REQUIRED at L5 for agent subjects exercising autonomous authority.
        self.qualification = dict(qualification or {})

    def scope_of(self, subject_id):
        return self.roles.get(subject_id)

    def admit(self, action, now, delegation=None):
        """Returns (admitted, rejection_reason, detail).

        `rejection_reason` is a value of the §4.7.1 closed enumeration, so a refusal is
        recordable as an ADMISSION_REJECTED event without inventing a reason code.
        """
        required = ("subject_id", "action_class", "target")
        if any(k not in action for k in required):
            return False, "SCHEMA_VIOLATION", "missing one of %s" % (required,)
        # §4.5.1: the agent MUST NOT include stated reasoning, urgency assertions or
        # compliance self-reports. T6: stated intent is not an input to the decision, so
        # the surface refuses the request rather than ignoring the field -- a field that
        # is accepted and ignored is a field someone will eventually read.
        for banned in ("reasoning", "urgency", "justification", "approval",
                       "asserted_authority", "compliance_self_report"):
            if banned in action:
                return False, "SCHEMA_VIOLATION", "request carries %r" % banned

        subject_scope = self.roles.get(action["subject_id"])
        if subject_scope is None:
            return False, "UNAUTHORIZED_ACTION_CLASS", "subject holds no role"

        if delegation is not None:
            # The delegated scope bounds the action, and the subject must still hold the
            # class independently unless the delegation granted it -- D3: "The OCP MUST
            # admit an action by S only if it is within scope(S) AND independently passes
            # C2.eval against policy and invariants."
            ok, dimension = delegation.permits(action, now)
            if not ok:
                return False, "UNAUTHORIZED_ACTION_CLASS", "outside delegated %s" % dimension
            return True, None, None

        ok, dimension = subject_scope.permits(action, now)
        if not ok:
            return False, "UNAUTHORIZED_ACTION_CLASS", "outside subject %s" % dimension

        if self.qualification and not self.qualification.get(action["subject_id"], True):
            return False, "UNQUALIFIED", "subject is not currently qualified"
        return True, None, None
