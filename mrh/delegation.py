"""Governed multi-agent delegation — Appendix L (D1-D5) and Invariant I8 (Part II §5.9).

I8 has two clauses, and they fail differently.

Clause (a), attenuation: "Along any delegation chain, effective authority MUST be
non-increasing from the authorizing subject ... scope(S) ⊆ scope(O) ⊆ … ⊆ scope(P). A
delegation MUST NOT grant a subject an action its delegator could not itself have
caused." This is what `Scope.contains` decides, on the five dimensions D3 names.

Clause (b), no laundering: "A governed action MUST be admitted only if it is
independently authorized for the subject that submits it. Consequently, no arrangement of
subjects — orchestration, hand-off, sequencing, or concurrent operation — MAY make
reachable a governed action that no participant was independently authorized to submit."
This one is not enforced here at all: it is enforced by the Agent Surface refusing an
action class the submitting subject does not hold, and by C6 refusing an ECC compiled for
another subject. Clause (b) is a property of the whole admission path, which is exactly
why NT-008 Part B applies to *every* deployment, delegating or not.

The subtlety in D3 that is easy to get wrong: parameter constraints compose by *logical
implication*, not by set inclusion. `constraints(A)` must imply `constraints(B)` — the
narrower predicate is the subset. Getting that backwards inverts the containment test and
admits every widening token, which is why the direction is asserted in the tests.
"""
import datetime
import hashlib
import hmac
import json
import uuid

# The C1-declared deterministic constraint profile these scopes are expressed in.
# §L.3 requires the predicate to be "expressed in the deterministic constraint profile
# declared by C1" -- naming the profile is what lets an assessor decide whether two
# predicates are even comparable, which §L.3 makes a fail-deny condition when they are not.
CONSTRAINT_PROFILE = "croa.allowed-values/1"
SCOPE_PROFILE_VERSION = "scope-profile-1.0.1"

_DELEGATION_KEY = b"CROA-MRH-DELEGATION-DEMO-KEY"


def _canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)


_FAR_FUTURE = "9999-12-31T23:59:59+00:00"


def _iso(epoch_seconds):
    """The schema types the window bounds as date-times, not as epoch floats."""
    if epoch_seconds == float("inf"):
        return _FAR_FUTURE
    return datetime.datetime.fromtimestamp(
        epoch_seconds, datetime.timezone.utc).isoformat()


def _canonical_time(epoch_seconds):
    """Round-trip a bound through the recorded form so comparison is well-defined."""
    if epoch_seconds in (float("inf"), float("-inf")):
        return epoch_seconds
    return _epoch(_iso(epoch_seconds))


def _epoch(iso):
    if iso == _FAR_FUTURE:
        return float("inf")
    return datetime.datetime.fromisoformat(iso).timestamp()


class Scope(object):
    """The canonical D3 scope profile (Appendix L §L.3).

    Six fields, five of which take part in the subset test. `subject_id` names whom the
    scope applies to and is not itself compared: a delegation necessarily changes it.
    """

    __slots__ = ("subject_id", "action_classes", "targets", "parameter_constraints",
                 "validity_window", "invariant_context", "policy_artifact_id")

    def __init__(self, subject_id, action_classes, targets, parameter_constraints=None,
                 validity_window=(0, float("inf")), invariant_context=None,
                 policy_artifact_id="pol-core-data-protection@1.4.0"):
        self.subject_id = subject_id
        self.policy_artifact_id = policy_artifact_id
        self.action_classes = frozenset(action_classes)
        self.targets = frozenset(targets)
        # A mapping action_class -> allowed value set. `None` for a class means
        # unconstrained, which is the *weakest* predicate and therefore the widest.
        self.parameter_constraints = dict(parameter_constraints or {})
        # Canonicalise the window to the resolution of the recorded form. §L.3 compares
        # scopes "after canonical resolution", and canonicalisation has to be idempotent:
        # a scope must still contain itself after a round trip through the record. The
        # recorded form is an ISO date-time, which is microsecond-resolution, so an
        # un-normalised float from time.time() compares as *wider* than its own recorded
        # value by a fraction of a microsecond -- and the delegation fails deny for a
        # widening that exists only in the representation.
        self.validity_window = (_canonical_time(validity_window[0]),
                                _canonical_time(validity_window[1]))
        self.invariant_context = invariant_context

    # ------------------------------------------------------- the D3 subset test
    def contains(self, other):
        """True iff `other` ⊆ `self` on all five dimensions. Returns (ok, failed_dimension).

        §L.3: "If the OCP cannot canonicalize a field, cannot prove predicate implication,
        sees incomparable policy models, or sees a stale/widened invariant context, the
        subset relation is not established and the delegation MUST fail-deny." So every
        branch here defaults to *not established*, never to "probably fine".
        """
        if not other.action_classes <= self.action_classes:
            return False, "action_classes"
        if not other.targets <= self.targets:
            return False, "targets"

        # (3) parameter_constraints(other) must IMPLY parameter_constraints(self).
        # Modelled as allowed-value sets: the implying predicate is the narrower set.
        for action_class, mine in self.parameter_constraints.items():
            theirs = other.parameter_constraints.get(action_class)
            if mine is None:
                continue                              # unconstrained implies everything
            if theirs is None:
                return False, "parameter_constraints"  # they relaxed a constraint I hold
            if not frozenset(theirs) <= frozenset(mine):
                return False, "parameter_constraints"

        # (4) validity_window(other) wholly contained in validity_window(self)
        if not (other.validity_window[0] >= self.validity_window[0]
                and other.validity_window[1] <= self.validity_window[1]):
            return False, "validity_window"

        # (5) invariant_context the same, or a governed narrowing
        if self.invariant_context is not None and other.invariant_context != self.invariant_context:
            return False, "invariant_context"
        return True, None

    def permits(self, action, now=None):
        """Whether this scope independently authorizes one concrete action."""
        if action["action_class"] not in self.action_classes:
            return False, "action_classes"
        if action["target"] not in self.targets:
            return False, "targets"
        allowed = self.parameter_constraints.get(action["action_class"])
        if allowed is not None and action.get("dataset") not in allowed:
            return False, "parameter_constraints"
        if now is not None:
            # Both sides canonical. The window bounds were rounded to the resolution of
            # the recorded form, and rounding can go *up*: comparing a canonical bound
            # against a raw time.time() reading rejects an action submitted in the same
            # microsecond the token was issued, roughly half the time. A comparison
            # between a canonicalised value and a raw one is not well-defined in either
            # direction, so both are canonicalised here.
            t_now = _canonical_time(now)
            if not (self.validity_window[0] <= t_now <= self.validity_window[1]):
                return False, "validity_window"
        return True, None

    def as_dict(self):
        """The canonical scope profile as it is recorded.

        Appendix L §L.3 names these fields `scope.subject_id`, `scope.action_classes`
        and so on; `event.schema.json` declares them unprefixed inside the `scope`
        object, with additionalProperties false. The prefixed form would nest to
        `scope.scope.action_classes`, so the prose notation reads as "the action_classes
        field of the scope profile" rather than as a literal key, and the schema's form
        is the one written. Recorded as a divergence between §L.3 and the companion
        schema in the v1.0.1 defect register.
        """
        return {
            "subject_id": self.subject_id,
            "action_classes": sorted(self.action_classes),
            "targets": sorted(self.targets),
            "parameter_constraints": {
                "profile": CONSTRAINT_PROFILE,
                "expression": dict((k, sorted(v) if v is not None else None)
                                   for k, v in self.parameter_constraints.items()),
            },
            "validity_window": {
                "not_before": _iso(self.validity_window[0]),
                "not_after": _iso(self.validity_window[1]),
            },
            "invariant_context": {
                "policy_artifact_id": self.policy_artifact_id,
                "invariant_set_version": self.invariant_context or "inv-unversioned",
                "scope_profile_version": SCOPE_PROFILE_VERSION,
            },
        }

    @classmethod
    def from_dict(cls, subject_id, recorded):
        """Rebuild a scope from its recorded canonical form.

        The admission path re-derives the scope from what the token carries rather than
        from what the caller says it means: a token is data the agent holds, and the
        only trustworthy reading of it is the one the OCP performs itself.
        """
        pc = recorded["parameter_constraints"]
        if pc.get("profile") != CONSTRAINT_PROFILE:
            # §L.3: "sees incomparable policy models ... the subset relation is not
            # established and the delegation MUST fail-deny."
            raise DelegationRejected(
                "constraint profile %r is not comparable with %r"
                % (pc.get("profile"), CONSTRAINT_PROFILE), "parameter_constraints")
        vw = recorded["validity_window"]
        return cls(subject_id, recorded["action_classes"], recorded["targets"],
                   dict(pc["expression"]),
                   (_epoch(vw["not_before"]), _epoch(vw["not_after"])),
                   recorded["invariant_context"]["invariant_set_version"],
                   recorded["invariant_context"]["policy_artifact_id"])

    def __repr__(self):
        return "<Scope %s classes=%s targets=%s>" % (
            self.subject_id, sorted(self.action_classes), sorted(self.targets))


class DelegationRejected(Exception):
    """A token that does not attenuate, has expired, or exceeds the declared depth."""

    def __init__(self, message, dimension=None):
        Exception.__init__(self, message)
        self.dimension = dimension


def issue_token(authorizing_scope, delegated_scope, now, ttl=60, max_depth=2, depth=1,
                parent_session_id=None):
    """Issue a delegation token (D2, D4).

    D3 is checked here, at issuance -- but checking it here is not the guarantee. A token
    is data the agent holds, and an agent that can hold a token can present a forged one.
    The admission path verifies the signature and re-checks containment, which is why
    `verify_token` exists and why the tests present a hand-built widening token.
    """
    ok, dimension = authorizing_scope.contains(delegated_scope)
    if not ok:
        raise DelegationRejected(
            "delegated scope widens %s beyond the authorizing subject's" % dimension,
            dimension)
    if depth > max_depth:
        raise DelegationRejected("delegation depth %d exceeds max_depth %d"
                                 % (depth, max_depth), "depth")
    token = {
        "gga.delegation.authorizing_subject": authorizing_scope.subject_id,
        "gga.delegation.scope": delegated_scope.as_dict(),
        "gga.delegation.expires_at": now + ttl,
        "gga.delegation.max_depth": max_depth,
        "gga.delegation.depth": depth,
        "gga.delegation.parent_session_id": parent_session_id,
    }
    token["gga.delegation.signature"] = hmac.new(
        _DELEGATION_KEY, _canon(token).encode(), hashlib.sha256).hexdigest()
    return token


def verify_token(token, authorizing_scope, delegated_scope, now):
    """Verify a presented token. Returns (ok, reason, dimension).

    Every check is a fail-deny branch: D4 for expiry and depth, D3 for containment.
    Signature first, because an unsigned token's contents are the agent's claim about its
    own authority and T6 makes that not an input to the decision.
    """
    unsigned = dict((k, v) for k, v in token.items()
                    if k != "gga.delegation.signature")
    expected = hmac.new(_DELEGATION_KEY, _canon(unsigned).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, token.get("gga.delegation.signature", "")):
        return False, "delegation token signature invalid", "signature"
    if now > token["gga.delegation.expires_at"]:
        return False, "delegation token expired", "validity_window"
    if token["gga.delegation.depth"] > token["gga.delegation.max_depth"]:
        return False, "delegation depth exceeds max_depth", "depth"
    ok, dimension = authorizing_scope.contains(delegated_scope)
    if not ok:
        return False, "delegated scope widens %s" % dimension, dimension
    return True, None, None


def build_chain(hops):
    """`event.delegation_chain` (§L.4): the ordered array of hops.

    Each hop carries "the hop's subject, its authorizing subject, the delegated scope in
    the canonical D3 scope profile, and the delegation-token signature". The request
    carries one immediate hop; C5 carries the whole chain, because attribution is to the
    chain and not to the last subject in it (D2).
    """
    chain = []
    for hop in hops:
        chain.append({
            "subject_id": hop["subject_id"],
            "authorizing_subject": hop["authorizing_subject"],
            "scope": hop["scope"],
            "token_signature": hop["token_signature"],
        })
    return chain


def new_session_id(prefix="sess"):
    return "%s-%s" % (prefix, uuid.uuid4().hex[:10])
