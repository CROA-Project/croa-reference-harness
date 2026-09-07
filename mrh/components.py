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
import datetime
import hashlib
import hmac
import json
import time
import uuid

from .invariants import AMBIGUOUS, VIOLATED, Invariant, InvariantRegistry
from .trajectory import C4Unavailable

_ECC_KEY = b"CROA-MRH-ECC-DEMO-KEY"


def _iso(epoch_seconds):
    """ecc.schema.json types the contract's timestamps as date-times, not as epoch
    floats. Emitting a float there is not a formatting preference: an assessor handed
    `1788783682.4` cannot tell a second from a millisecond without knowing which
    language produced it, which is exactly the reconstructability §4.4.1 asks for."""
    return datetime.datetime.fromtimestamp(
        epoch_seconds, datetime.timezone.utc).isoformat()


def _epoch(iso):
    return datetime.datetime.fromisoformat(iso).timestamp()


#: Fields that identify *where* a request came from rather than *what* it does.
#: An authorization is bounded to an operation (§4.3.1: action class, target, window),
#: so binding it to these as well would refuse the same authorized operation merely
#: because it arrived in a different session -- a constraint §4.3.1 does not impose.
_CONTEXTUAL_FIELDS = ("session_id", "gar_id")


def operation_fingerprint(action, subject_id=None):
    """Canonical identity of the operation an authorization is bound to."""
    op = dict((k, v) for k, v in action.items() if k not in _CONTEXTUAL_FIELDS)
    if subject_id is not None:
        op["subject_id"] = subject_id
    return hashlib.sha256(_canon(op).encode()).hexdigest()


def _canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


class CommitmentMismatch(Exception):
    """What is presented at the boundary is not what the contract authorizes."""


class NotGrounded(Exception):
    """C7 was handed something other than C3's grounded governed action. Raising is
    the point: an ECC compiled from an ungrounded request is the remaining half of
    H-03, and it must not be constructible."""


class PolicyIncomplete(Exception):
    """C1 was asked for something it has not been told. Fail-deny, never a default:
    §2.6's rule is that a determination which cannot be made is a determination that
    failed, and a silently assumed R0 is the most expensive possible guess."""


class AuthorizationInvalid(Exception):
    """The authorization is unsigned, expired, or not bound to this action.

    Distinct from an authorization that is merely *spent*: spent is a fact only the
    redemption registry can establish, and only at admission.
    """


# --- C1: Policy Authority -------------------------------------------------
class PolicyAuthority(object):
    """Holds registered invariants and issues signed, time-bounded authorization
    artifacts for governed exceptions (§4.3.1). The agent can never issue these."""

    #: Reversibility class per governed action class (Part I, T5; §4.4.1). An ECC
    #: carries the class of the transition it authorizes, so an assessor can see what
    #: was at stake without re-deriving it. There is no default on purpose: an action
    #: class whose consequence nobody has classified is one nobody has thought about,
    #: and C7 fails-deny rather than guessing R0.
    DEFAULT_REVERSIBILITY = {
        "data.read": "R0",          # fully reversible: a read changes nothing
        "data.export": "R2",        # irreversible, low impact: the copy is out
        "report.generate": "R1",    # compensatable: the report can be withdrawn
        "sql.execute": "R3",        # irreversible, high impact
        "infra.delete": "R4",       # irreversible, catastrophic
    }

    #: Controls recorded in the ECC for any transition of class R1 or above
    #: (§2.5.1, T5; required by ecc.schema.json whenever the class is not R0). Only R1
    #: admits an actual compensation; above it the recorded control is *preventive*,
    #: and calling it compensatory would be the false comfort T5 exists to refuse.
    DEFAULT_CONTROLS = {
        "R1": [{"control_id": "CTL-COMPENSATE-01", "kind": "compensating",
                "description": "Inverse operation available; the transition can be "
                               "undone by an operator without data loss."}],
        "R2": [{"control_id": "CTL-PREAUTH-01", "kind": "preventive",
                "description": "T5 pre-execution authorization beyond the standard "
                               "permit decision. No inverse path exists."}],
        "R3": [{"control_id": "CTL-STAGED-01", "kind": "preventive",
                "description": "Staged execution with an abort point, and enhanced "
                               "monitoring of the target for the duration."}],
        "R4": [{"control_id": "CTL-DUAL-01", "kind": "preventive",
                "description": "Dual authorization and a mandatory hold window. "
                               "Nothing compensates an R4 transition."}],
    }

    def __init__(self, approved_export_targets, invariant_set_version="inv-2026-09-01",
                 policy_artifact_id="pol-core-data-protection@1.4.0", registry=None,
                 reversibility=None, controls=None):
        self.approved_export_targets = set(approved_export_targets)
        self.reversibility = dict(reversibility if reversibility is not None
                                  else self.DEFAULT_REVERSIBILITY)
        self.controls = dict(controls if controls is not None else self.DEFAULT_CONTROLS)
        # §4.7.1 requires every decision event to name the C1 artifact it was issued
        # under, so a decision can be re-derived years later against the policy that
        # actually applied to it (I3).
        self.policy_artifact_id = policy_artifact_id
        self.registry = registry if registry is not None else self._default_registry()
        self.registry.version = invariant_set_version

    def reversibility_class_for(self, action_class):
        """§4.4.1: raises rather than defaulting. See DEFAULT_REVERSIBILITY."""
        try:
            return self.reversibility[action_class]
        except KeyError:
            raise PolicyIncomplete(
                "no reversibility class registered for action class %r; C1 cannot "
                "authorize a transition whose consequence class is undeclared"
                % action_class)

    def compensating_controls_for(self, reversibility_class):
        """The controls an ECC must record for this class. Empty for R0, which is the
        only class the schema lets an ECC carry none for."""
        if reversibility_class == "R0":
            return []
        try:
            return [dict(c) for c in self.controls[reversibility_class]]
        except KeyError:
            raise PolicyIncomplete(
                "no compensating or preventive control registered for reversibility "
                "class %r; T5 does not permit an irreversible transition to be "
                "authorized with nothing recorded against it" % reversibility_class)

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
            "action_fingerprint": operation_fingerprint(action),
            "expiry": now + ttl,
            "redemption_policy": "single-use",
            "exception_scope": {
                "waived_invariants": list(waived),
                "action_class": action["action_class"],
                "target_constraints": [action["target"]],
                # date-time, not an epoch float: this object is copied verbatim into
                # the ECC and is validated there.
                "expires_at": _iso(now + ttl),
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
            auth["action_fingerprint"], operation_fingerprint(action))


# --- C3: Path Resolver ----------------------------------------------------
class PathResolver(object):
    """Grounds a request against the Federated Context Registry (§4.5.2).

    `available=False` models the registry being unreachable or its snapshot too old.
    §4.5 is explicit that this is fail-closed and not merely a resolution failure: "a
    grounding that cannot be performed is treated as a grounding that failed", and the
    pipeline MUST NOT fall through to C2.
    """

    NON_PARAMETER_FIELDS = ("subject_id", "action_class", "target", "session_id",
                            "gar_id")

    def __init__(self, context_registry, available=True):
        self.context_registry = set(context_registry)
        self.available = available

    def resolve(self, target):
        """The membership test alone. Kept because two negative tests assert on it
        directly; the pipeline uses `ground` below."""
        if not self.available:
            return False
        return target in self.context_registry

    def ground(self, action, now=None):
        """Return the grounded governed action (`gga.*`) for a request, or None.

        §4.5.1: C3 does not answer yes or no, it *produces an artifact* -- the request
        plus the record of what was resolved against the registry and what was not.
        That record is what makes a decision reconstructable months later, and it is
        what `ecc.action` is required to carry.

        `now` is a parameter rather than a call to the clock, because `resolved_at` is
        part of the grounding record, the grounding record is part of the ECC, and
        `ecc.id` is a content address over it. A hidden clock reading here would make
        the contract identity non-reproducible -- grounding the same request twice a
        microsecond apart would yield two contracts. That is *correct*: a grounding has
        a time, and a contract built on a later grounding is a different contract. It
        just must not happen by accident.

        The harness previously returned a boolean here and passed the raw request
        onward. Everything downstream then described a governed action that had never
        been grounded by anything, and the ECC could not validate against its own
        schema -- recorded as the remaining half of H-03.

        Returns None when grounding fails **or cannot be performed**: §4.5 is explicit
        that an unreachable or stale registry is treated as a grounding that failed,
        and the caller must not fall through to C2. The two cases are distinguishable
        by `self.available`, because C5 records them differently.
        """
        if not self.available or action["target"] not in self.context_registry:
            return None
        now = time.time() if now is None else now
        parameters = dict((k, v) for k, v in action.items()
                          if k not in self.NON_PARAMETER_FIELDS)
        return {
            # Deterministic when the caller supplies no GAR id. A random one here
            # would make `ecc.id` non-reproducible, and `ecc.id` is a content address:
            # grounding the same request twice must yield the same contract identity,
            # or H-03's whole property is decorative.
            "gga.request_id": action.get(
                "gar_id", "gar-" + operation_fingerprint(action)[:16]),
            "gga.type": action["action_class"],
            "gga.target": action["target"],
            "gga.parameters": parameters,
            # Every reference this request made, resolved. The demonstrator grounds one
            # entity -- the target -- so the list has one member; a deployment resolves
            # every reference in the request against the Federated Context Registry.
            "gga.resolved_entities": [{
                "canonical_id": action["target"],
                # All this registry can attest is membership. A deployment records what
                # it actually resolved to -- a schema version, a repository HEAD, a
                # document revision -- and `state` is where that goes. Writing
                # "PRESENT" is the honest ceiling of a set-membership registry, and
                # saying so is better than inventing a richer state it never read.
                "state": "PRESENT",
                "resolved_at": _iso(now),
                "registry": "mrh-context-registry",
            }],
            "gga.unresolved_refs": [],
            "gga.semantic_result": "GROUNDED",
        }


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

    def __init__(self, c1, signer_id="c7-mrh-demonstrator"):
        self.c1 = c1
        # §4.4.1 requires the contract to name who signed it, for the same reason
        # §4.7.1 requires it of an event: a signature nobody is named for cannot be
        # revoked, rotated, or disbelieved.
        self.signer_id = signer_id

    def compile(self, gga, subject_id, now, permit_event_id, session_id=None,
                authorization=None, ttl=300, additional_scope=None):
        """Produce an ECC (§4.4.1).

        `subject_id` is the **authenticated** identity the permit was issued for, and it
        is mandatory. It used to be read out of the request payload, which is the same
        mistake H-02 fixed at the boundary and left standing here: a contract must be
        compiled for whoever the decision was about, not for whoever the request says.
        The grounded action carries no subject, and the schema is right that it should
        not -- the subject belongs to the GAR and to the contract, not to the grounding.

        `gga` is the **grounded governed action** produced by C3, not the raw request.
        The distinction is the remaining half of H-03: a contract carrying the request
        describes an action nothing has grounded, and `ecc.action` is required by
        §4.5.1 and by the schema to be a GROUNDED `gga.*`. Passing anything else raises
        rather than compiling something that will not validate -- the unsafe call is not
        expressible, which is the shape the H-02 fix used for the same reason.

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
        if not isinstance(gga, dict) or gga.get("gga.semantic_result") != "GROUNDED":
            raise NotGrounded(
                "ecc.action must be a grounded governed action from C3 "
                "(gga.semantic_result == GROUNDED); got %r"
                % (gga.get("gga.semantic_result") if isinstance(gga, dict) else type(gga).__name__))

        action = self._request_of(gga)
        reversibility = self.c1.reversibility_class_for(action["action_class"])
        content = {
            "ecc.action": gga,
            "ecc.subject": subject_id,
            "ecc.session_id": session_id or ("sess-" + subject_id),
            "ecc.permit_event_id": permit_event_id,
            "ecc.policy_artifact_id": self.c1.policy_artifact_id,
            "ecc.reversibility_class": reversibility,
            "ecc.compiled_at": _iso(now),
            "ecc.expires_at": _iso(now + ttl),
            "ecc.invariant_set_version": self.c1.invariant_set_version,
            "ecc.signer_id": self.signer_id,
            "ecc.authorization_scope": [{
                "target": action["target"],
                "action_type": action["action_class"],
            }] + list(additional_scope or []),
            "ecc.decision_basis": "PERMIT" if authorization is None else "PERMIT_WITH_AUTHORIZATION",
        }
        controls = self.c1.compensating_controls_for(reversibility)
        if controls:
            # Required by the schema for R1 and above, and absent for R0 -- recording
            # an empty list against a fully reversible transition would suggest someone
            # looked for a control and found none.
            content["ecc.compensating_controls"] = controls
        if authorization is not None:
            if not self.c1.authorization_valid_for(
                    authorization, dict(action, subject_id=subject_id), now):
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

    @staticmethod
    def _request_of(gga):
        return request_of(gga)


# --- C6: Execution Firewall ----------------------------------------------
def request_of(gga):
    """Project a grounded governed action back to the concrete operation it describes.

    C6 compares an *operation* -- what the presenter is actually asking to do -- against
    the contract. That comparison is over the action class, the target and the
    parameters, which is what this returns. It is not a reconstruction of the original
    request and must not be treated as one: the grounding record stays in the ECC,
    where an assessor can see it.
    """
    op = {"action_class": gga["gga.type"], "target": gga["gga.target"]}
    op.update(gga.get("gga.parameters") or {})
    return op


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
        if now > _epoch(ecc["ecc.expires_at"]):
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
