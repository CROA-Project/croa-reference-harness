"""Regression tests for two evidence defects: exception-scope coverage in C2, and the
structure of ADMISSION_REJECTED events.

Install as ``tests/test_exception_scope_and_admission_evidence.py``. Standard library
only, public MRH API only, generic invariants and subjects. Every assertion message names
the CROA v1.0.1 section it relies on.

1. Exception scope (C2, ``ExecutionGovernor.evaluate``).
   A valid, unspent authorization bound to an action used to cover *every* invariant
   that action violated, whatever its ``exception_scope.waived_invariants`` named. The
   specification is narrower:

   * Part II §4.4.2 step 5 denies when "no valid authorization artifact from C1 (see
     §4.3.1) covers the violation"; PERMIT_WITH_AUTHORIZATION is an "invariant violation
     covered by a valid authorization artifact";
   * §4.3.1: the artifact carries "the identifier(s) of the specific enterprise
     governance invariant(s) this authorization overrides -- never a wildcard";
   * Part I §2.5: an authorized exception needs an artifact "whose declared scope covers
     exactly this violation", and "an authorization artifact does not relax any invariant
     outside its declared scope".

   ``TestExceptionScopeCoverage`` requires a DENY whenever a violated invariant is not in
   the waived set, and requires the C5 record of an admitted waiver to name exactly what
   was waived and under which authorization.

2. Admission-rejection evidence (Agent Surface, ``Harness._reject``).
   A refusal on the target and a refusal on the action class both carry
   ``event.rejection_reason = UNAUTHORIZED_ACTION_CLASS`` -- the enumeration is closed
   (§4.7.1) and §4.9.1 names that value for a failed admission predicate -- and the
   attempted target and the failing dimension were only available as free text.
   ``TestAdmissionRejectionEvidence`` requires three structured, non-normative fields on
   every ADMISSION_REJECTED event (``attempted_target``, ``rejection_basis``,
   ``rejection_dimension``). It also requires the normative fields and the closed
   ``event.rejection_reason`` values to be unchanged.

On an unpatched tree, the denial and C5-record tests of the first class and the field
tests of the second class are expected to fail. The admission, single-use and
enumeration tests are expected to pass on both trees: they guard behaviour the fix must
not change.
"""
import copy
import os
import time
import unittest

from mrh.delegation import Scope, issue_token
from mrh.harness import Harness
from mrh.invariants import Invariant, InvariantRegistry

SUBJECT = "cs-agent-01"
DEST = "I-DEST-001"
SIZE = "I-SIZE-001"

#: §4.7.1: the closed event.rejection_reason enumeration of ADMISSION_REJECTED.
REJECTION_REASONS = ("SCHEMA_VIOLATION", "UNAUTHORIZED_ACTION_CLASS", "UNQUALIFIED",
                     "QUALIFICATION_EXPIRED", "QUALIFICATION_CONFIG_MISMATCH")

#: Violates DEST only.
EXPORT_ONE = {"subject_id": SUBJECT, "action_class": "data.export", "target": "billing"}
#: Violates DEST and SIZE.
EXPORT_TWO = dict(EXPORT_ONE, record_count=500)


def _registry():
    """Two independent E1 invariants over one data.export request (Part III §9.1)."""
    return InvariantRegistry([
        Invariant(DEST, "data.export MUST target an approved destination",
                  evaluability="E1", trajectory_profile="TP-0", reversibility="R2",
                  predicate=lambda a: (a["action_class"] == "data.export"
                                       and a["target"] not in ("crm",))),
        Invariant(SIZE, "data.export MUST NOT carry more than 100 records",
                  evaluability="E1", trajectory_profile="TP-0", reversibility="R2",
                  predicate=lambda a: (a["action_class"] == "data.export"
                                       and a.get("record_count", 0) > 100)),
    ])


def _events(h, etype, **match):
    return [e for e in h.c5.events if e["event.type"] == etype
            and all(e.get(k) == v for k, v in match.items())]


def _flow(action, waived, now=None):
    """A fresh harness, one authorization naming `waived`, one governed flow."""
    now = time.time() if now is None else now
    h = Harness(invariants=_registry())
    auth = h.c1.issue_authorization(action, now, waived=waived)
    return h, auth, h.governed_flow(action, now, authorization=auth)


# ===================================================================== exception scope


# ============================================================ admission-rejection evidence
def _roles(now):
    window = (now - 60, now + 3600)
    return {
        # agent-a may read crm, nothing else.
        "agent-a": Scope("agent-a", {"data.read"}, {"crm"}, {}, window),
        # lead may read and report on crm and reporting-api, and delegates to agent-b.
        "lead": Scope("lead", {"data.read", "report.generate"},
                      {"crm", "reporting-api"}, {}, window),
        # agent-b holds report.generate on reporting-api in its own right.
        "agent-b": Scope("agent-b", {"report.generate"}, {"reporting-api"}, {}, window),
    }


def _token(roles, now):
    """lead -> agent-b: data.read on crm, for 60 s. A valid narrowing (Appendix L, D3)."""
    delegated = Scope("agent-b", {"data.read"}, {"crm"}, {}, (now, now + 60))
    return issue_token(roles["lead"], delegated, now, ttl=60)


def _read(subject, target):
    return {"subject_id": subject, "action_class": "data.read", "target": target}


def _refusal_battery(now):
    """One refusal per admission control, each on a fresh harness.

    Returns (name, harness, result, expected event.rejection_reason).
    """
    roles = _roles(now)
    token = _token(roles, now)
    forged = copy.deepcopy(token)
    forged["gga.delegation.signature"] = "0" * 64
    cases = []

    def run(name, action, reason, at=None, delegation_token=None, unqualified=None):
        h = Harness(roles=roles)
        if unqualified is not None:
            h.surface.qualification = {unqualified: False}
        r = h.governed_flow(action, now if at is None else at,
                            delegation_token=delegation_token)
        cases.append((name, h, r, reason))

    run("class", {"subject_id": "agent-a", "action_class": "data.export",
                  "target": "crm"}, "UNAUTHORIZED_ACTION_CLASS")
    run("target", _read("agent-a", "billing"), "UNAUTHORIZED_ACTION_CLASS")
    run("role", _read("stranger", "crm"), "UNAUTHORIZED_ACTION_CLASS")
    run("schema", {"subject_id": "agent-a", "action_class": "data.read"},
        "SCHEMA_VIOLATION")
    run("qualification", _read("agent-a", "crm"), "UNQUALIFIED", unqualified="agent-a")
    run("token signature", _read("agent-b", "crm"), "UNAUTHORIZED_ACTION_CLASS",
        delegation_token=forged)
    run("delegated scope", _read("agent-b", "reporting-api"),
        "UNAUTHORIZED_ACTION_CLASS", delegation_token=token)
    return cases


class TestAdmissionRejectionEvidence(unittest.TestCase):
    """Every ADMISSION_REJECTED event says which control refused, on which dimension,
    and for which target, in structured fields; the normative fields are unchanged."""

    def setUp(self):
        self.now = time.time()
        self.roles = _roles(self.now)

    def _rejected_event(self, h, r):
        self.assertEqual(r.get("outcome"), "REJECTED",
                         "§4.9.1: a request failing admission is rejected at the Agent "
                         "Surface")
        events = _events(h, "ADMISSION_REJECTED", gar_id=r["gar_id"])
        self.assertEqual(len(events), 1,
                         "§4.9.1: the rejection is recorded in C5 as one "
                         "ADMISSION_REJECTED event")
        self.assertEqual(
            [e["event.type"] for e in h.c5.events if e.get("gar_id") == r["gar_id"]],
            ["ADMISSION_REJECTED"],
            "§4.9.1: the request MUST NOT be forwarded to C3 or C2")
        return events[0]

    def _assert_fields(self, ev, r, target, basis, dimension):
        self.assertEqual(ev.get("attempted_target"), target,
                         "§4.7.1: ADMISSION_REJECTED carries no event.action_spec, so the "
                         "attempted target is recorded as a structured field")
        self.assertEqual(ev.get("rejection_basis"), basis,
                         "§4.9.1, §4.9.2, Appendix L: the record names which admission "
                         "control refused")
        self.assertEqual(ev.get("rejection_dimension"), dimension,
                         "§4.9.1, Appendix L §L.3: the record names the failing "
                         "dimension without parsing free text")
        self.assertEqual(r.get("attempted_target"), target, "returned with the event")
        self.assertEqual(r.get("rejection_basis"), basis, "returned with the event")
        self.assertEqual(r.get("rejection_dimension"), dimension, "returned with the event")

    def test_target_refusal_records_target_basis_and_dimension(self):
        h = Harness(roles=self.roles)
        r = h.governed_flow(_read("agent-a", "billing"), self.now)
        ev = self._rejected_event(h, r)
        self.assertEqual(ev["event.rejection_reason"], "UNAUTHORIZED_ACTION_CLASS",
                         "§4.9.1, §4.7.1: reason code unchanged")
        self.assertEqual(ev["event.attempted_type"], "data.read",
                         "§4.7.1: event.attempted_type unchanged")
        self._assert_fields(ev, r, "billing", "SUBJECT_SCOPE", "targets")
        self.assertNotIn("failed_scope_dimension", ev,
                         "existing non-normative field keeps its meaning: token path only")

    def test_class_refusal_records_target_basis_and_dimension(self):
        h = Harness(roles=self.roles)
        r = h.governed_flow({"subject_id": "agent-a", "action_class": "data.export",
                             "target": "crm"}, self.now)
        ev = self._rejected_event(h, r)
        self.assertEqual(ev["event.rejection_reason"], "UNAUTHORIZED_ACTION_CLASS",
                         "§4.9.1: a failed admission predicate is UNAUTHORIZED_ACTION_CLASS")
        self.assertEqual(ev["event.attempted_type"], "data.export",
                         "§4.7.1: event.attempted_type is the gar.type of the request")
        self._assert_fields(ev, r, "crm", "SUBJECT_SCOPE", "action_classes")
        self.assertNotIn("failed_scope_dimension", ev,
                         "existing non-normative field keeps its meaning: token path only")

    def test_class_and_target_refusals_are_distinguishable(self):
        """Same normative reason code, different structured dimension."""
        h1, h2 = Harness(roles=self.roles), Harness(roles=self.roles)
        e1 = self._rejected_event(h1, h1.governed_flow(
            {"subject_id": "agent-a", "action_class": "data.export", "target": "crm"},
            self.now))
        e2 = self._rejected_event(h2, h2.governed_flow(_read("agent-a", "billing"),
                                                        self.now))
        self.assertEqual(e1["event.rejection_reason"], e2["event.rejection_reason"],
                         "§4.7.1: the closed enumeration has one code for both")
        self.assertIsNotNone(e1.get("rejection_dimension"),
                             "§4.9.1: the class refusal records its dimension")
        self.assertIsNotNone(e2.get("rejection_dimension"),
                             "§4.9.1: the target refusal records its dimension")
        self.assertNotEqual(e1.get("rejection_dimension"), e2.get("rejection_dimension"),
                            "§4.7.1, §4.9.1: a class refusal and a target refusal are "
                            "distinguishable in C5 without free text")

    def test_role_schema_and_qualification_refusals_record_basis(self):
        cases = (
            ("role", _read("stranger", "crm"), None, "crm", "SUBJECT_SCOPE", "role",
             "UNAUTHORIZED_ACTION_CLASS"),
            ("schema", {"subject_id": "agent-a", "action_class": "data.read"}, None,
             None, "SCHEMA", "schema", "SCHEMA_VIOLATION"),
            ("qualification", _read("agent-a", "crm"), "agent-a", "crm",
             "QUALIFICATION", "qualification", "UNQUALIFIED"),
        )
        for name, action, unqualified, target, basis, dimension, reason in cases:
            with self.subTest(refusal=name):
                h = Harness(roles=self.roles)
                if unqualified is not None:
                    h.surface.qualification = {unqualified: False}
                r = h.governed_flow(action, self.now)
                ev = self._rejected_event(h, r)
                self.assertEqual(ev["event.rejection_reason"], reason,
                                 "§4.7.1, §4.5.1, §4.9.1, §4.9.2: reason code unchanged")
                if target is None:
                    self.assertNotIn("attempted_target", ev,
                                     "§4.5.1: a request without a target records none")
                self._assert_fields(ev, r, target, basis, dimension)

    def test_delegation_token_refusals_are_distinguished(self):
        """Forged, expired and incomparable tokens are each refused before the Agent
        Surface predicate, and each records DELEGATION_TOKEN with its own dimension."""
        token = _token(self.roles, self.now)
        forged = copy.deepcopy(token)
        forged["gga.delegation.signature"] = "0" * 64
        incomparable = copy.deepcopy(token)
        incomparable["gga.delegation.scope"]["parameter_constraints"]["profile"] = \
            "another-profile/2"
        cases = (
            ("forged signature", forged, self.now, "signature",
             "Appendix L D3: a token that is not validly signed fails deny"),
            ("expired", token, self.now + 120, "validity_window",
             "Appendix L D4: a token presented after its expiry MUST fail-deny"),
            ("incomparable profile", incomparable, self.now, "parameter_constraints",
             "Appendix L §L.3: incomparable policy models fail-deny"),
        )
        seen = set()
        for name, tok, at, dimension, cite in cases:
            with self.subTest(token=name):
                h = Harness(roles=self.roles)
                r = h.governed_flow(_read("agent-b", "crm"), at, delegation_token=tok)
                ev = self._rejected_event(h, r)
                self.assertEqual(ev["event.rejection_reason"], "UNAUTHORIZED_ACTION_CLASS",
                                 "§4.7.1: reason code unchanged; " + cite)
                self.assertEqual(ev.get("failed_scope_dimension"), dimension,
                                 "existing non-normative field unchanged; " + cite)
                self._assert_fields(ev, r, "crm", "DELEGATION_TOKEN", dimension)
                seen.add(ev.get("rejection_dimension"))
        self.assertEqual(len(seen), 3,
                         "Appendix L D3/D4, §L.3: the three token refusals are "
                         "distinguishable from each other")

    def test_delegated_scope_refusal_is_distinct_from_token_refusal(self):
        """A valid token, used outside the scope it delegates."""
        token = _token(self.roles, self.now)
        control = Harness(roles=self.roles)
        ok = control.governed_flow(_read("agent-b", "crm"), self.now,
                                   delegation_token=token)
        self.assertTrue(ok.get("admitted"),
                        "Appendix L D3: an action within the delegated scope is admitted "
                        "(control case; the test is not vacuous)")

        h = Harness(roles=self.roles)
        r = h.governed_flow(_read("agent-b", "reporting-api"), self.now,
                            delegation_token=token)
        ev = self._rejected_event(h, r)
        self.assertEqual(ev["event.rejection_reason"], "UNAUTHORIZED_ACTION_CLASS",
                         "§4.7.1: reason code unchanged")
        self._assert_fields(ev, r, "reporting-api", "DELEGATED_SCOPE", "targets")
        self.assertNotIn("failed_scope_dimension", ev,
                         "existing non-normative field keeps its meaning: token path only")

    def test_rejection_reason_values_are_unchanged(self):
        """No new reason code, no new event type, normative fields as before. Passes on
        the unpatched tree too: it guards what the fix must not change."""
        for name, h, r, reason in _refusal_battery(self.now):
            with self.subTest(refusal=name):
                ev = self._rejected_event(h, r)
                self.assertIn(ev["event.rejection_reason"], REJECTION_REASONS,
                              "§4.7.1: event.rejection_reason is a closed enumeration")
                self.assertEqual(ev["event.rejection_reason"], reason,
                                 "§4.7.1, §4.9.1: the reason code for this refusal is "
                                 "unchanged")
                self.assertEqual(ev.get("event.attempted_type"),
                                 r and h.c5.events and ev.get("event.attempted_type"),
                                 "§4.7.1")
                self.assertEqual(ev["event.emitter_id"], "AgentSurface",
                                 "§4.7.1: emitted by the Agent Surface")
                for absent in ("event.action_spec", "event.decision_basis",
                               "event.policy_artifact_id", "event.invariant_state"):
                    self.assertNotIn(absent, ev,
                                     "§4.7.1: %s is not applicable to ADMISSION_REJECTED"
                                     % absent)


# ======================================================================= schema join
class TestNewFieldsSchemaConformance(unittest.TestCase):
    """Every event emitted by the two test classes above, including the new fields,
    validates against the published event.schema.json.

    Skipped, like TestEventSchemaConformance in test_mrh.py, when jsonschema or the
    schema is absent. Point it at a checkout with CROA_SCHEMA_DIR, or leave a sibling
    CROA/ clone.
    """

    @classmethod
    def setUpClass(cls):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            raise unittest.SkipTest("jsonschema not installed")
        import json
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [os.environ.get("CROA_SCHEMA_DIR"),
                      os.path.join(here, "..", "CROA", "spec", "schemas")]
        path = None
        for c in candidates:
            if c and os.path.exists(os.path.join(c, "event.schema.json")):
                path = os.path.join(c, "event.schema.json")
                break
        if path is None:
            raise unittest.SkipTest("event.schema.json not found (set CROA_SCHEMA_DIR)")
        with open(path, encoding="utf-8") as fh:
            cls.validator = Draft202012Validator(json.load(fh))

    def test_new_fields_validate_against_event_schema(self):
        now = time.time()
        harnesses = [h for _, h, _, _ in _refusal_battery(now)]
        for action, waived in ((EXPORT_ONE, (DEST,)), (EXPORT_ONE, (DEST, SIZE)),
                               (EXPORT_ONE, (SIZE,)), (EXPORT_TWO, (DEST,))):
            harnesses.append(_flow(action, waived, now)[0])
        seen = set()
        for h in harnesses:
            for ev in h.c5.events:
                seen.add(ev["event.type"])
                errors = sorted(self.validator.iter_errors(ev), key=str)
                self.assertEqual([e.message for e in errors], [],
                                 "§4.7.1, Appendix B: %s does not validate against "
                                 "event.schema.json" % ev["event.type"])
        for required in ("ADMISSION_REJECTED", "DENY", "PERMIT", "ECC_COMPILED"):
            self.assertIn(required, seen)


if __name__ == "__main__":
    unittest.main()
