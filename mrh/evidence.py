"""Evidence Pack generation — Appendix Q Part 1.

Appendix Q shows what an assessor is handed: worked examples of each governance event
type (Q.1.1-Q.1.7) and a structured negative-test report (Q.1.8). This module produces
both from a real run rather than from a template, which is the only version worth having.
A pack assembled by hand attests to the care of whoever assembled it; a pack extracted
from the C5 chain attests to what the system did.

What the pack does and does not establish is worth being exact about, because the
distinction is the whole of Part VI §29.4. The pack shows that the recorded decisions are
internally coherent, unaltered and correctly ordered. It does not show that every governed
action produced an event -- that follows from the fail-closed gate (I6/I6.1) and is
corroborated by cross-checks against the governed systems' own logs, which no
self-contained harness can perform on itself. `verification` below reports the first and
says so about the second.
"""
import datetime
import json


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class NegativeTestResult(object):
    """One reference negative test's outcome, in the Q.1.8 shape."""

    def __init__(self, test_id, test_name, setup, inputs, expected, actual, passed,
                 event_ids, notes=""):
        self.test_id = test_id
        self.test_name = test_name
        self.setup = setup
        self.inputs = inputs
        self.expected = expected
        self.actual = actual
        self.passed = passed
        self.event_ids = event_ids
        self.notes = notes

    def as_dict(self, assessor="CROA Minimal Reference Harness (self-test)"):
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "test_date": datetime.date.today().isoformat(),
            "tested_by": assessor,
            "assessment_reference": "Part VI Chapter 29 — Mechanical Enforcement Evidence",
            "setup_summary": self.setup,
            "input_summary": self.inputs,
            "expected_results": self.expected,
            "actual_results": self.actual,
            "pass_fail": "PASS" if self.passed else "FAIL",
            "c5_evidence_chain_reference": self.event_ids,
            "assessor_notes": self.notes,
        }


class EvidencePack(object):
    """An Appendix Q Part 1 pack extracted from a C5 record."""

    def __init__(self, audit, deployment="croa-mrh-demonstrator", profile="CROA Core"):
        self.audit = audit
        self.deployment = deployment
        self.profile = profile
        self.tests = []

    def add_test(self, result):
        self.tests.append(result)
        return result

    # ------------------------------------------------------- Q.1.1 - Q.1.7
    def worked_examples(self):
        """One recorded event per type present, in the order Appendix Q lists them.

        Only types that actually occurred are included. Emitting a placeholder for an
        absent type would turn the pack into a claim about what the deployment can do
        rather than a record of what it did.
        """
        order = ["PERMIT", "DENY", "CONTEXT_FAILURE", "ECC_COMPILED",
                 "EXECUTION_AUTHORIZED", "EXECUTION_BLOCKED", "TRAJECTORY_ALERT",
                 "ADMISSION_REJECTED", "EXECUTION_COMPLETED", "EXECUTION_FAILED",
                 "EFFECT_ATTESTED", "QUALIFICATION", "POLICY_ARTIFACT_ISSUED"]
        seen, examples = set(), []
        for etype in order:
            for ev in self.audit.events:
                if ev["event.type"] == etype and etype not in seen:
                    seen.add(etype)
                    examples.append(ev)
                    break
        return examples

    def coverage(self):
        counts = {}
        for ev in self.audit.events:
            counts[ev["event.type"]] = counts.get(ev["event.type"], 0) + 1
        return counts

    # --------------------------------------------------------- verification
    def verification(self):
        chain_ok, chain_msg = self.audit.verify_chain()
        corr_ok, corr_msg = self.audit.verify_decisions()
        return {
            "chain_integrity": {"ok": chain_ok, "detail": chain_msg},
            "decision_correlation": {"ok": corr_ok, "detail": corr_msg},
            "does_not_establish": [
                "That every governed action produced an event. C5 completeness follows "
                "from the fail-closed gate (I6/I6.1) and is corroborated by cross-checks "
                "against the governed systems' own access logs (Part VI §29.4), which a "
                "self-contained harness cannot perform on itself.",
                "That a production implementation has these properties. The code that "
                "enforces the rule and the assertion that checks it are the same program.",
            ],
        }

    # ---------------------------------------------------------------- pack
    def build(self):
        passed = [t for t in self.tests if t.passed]
        return {
            "pack_type": "CROA Evidence Pack",
            "specification_version": "1.0.1",
            "generated_at": _now(),
            "deployment": self.deployment,
            "conformance_profile": self.profile,
            "event_coverage": self.coverage(),
            "worked_examples": self.worked_examples(),
            "negative_tests": [t.as_dict() for t in self.tests],
            "negative_test_summary": {
                "executed": len(self.tests),
                "passed": len(passed),
                "failed": len(self.tests) - len(passed),
                "ids": [t.test_id for t in self.tests],
            },
            "verification": self.verification(),
            "total_events": len(self.audit.events),
        }

    def write(self, path):
        pack = self.build()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(pack, fh, indent=2, sort_keys=True, default=str)
            fh.write("\n")
        return pack

    # --------------------------------------------------------------- report
    def summary(self):
        pack = self.build()
        v = pack["verification"]
        lines = ["CROA Evidence Pack — specification v1.0.1",
                 "deployment: %s   profile: %s" % (self.deployment, self.profile),
                 "events: %d   types: %d" % (pack["total_events"], len(pack["event_coverage"]))]
        for etype, n in sorted(pack["event_coverage"].items()):
            lines.append("    %-24s %d" % (etype, n))
        s = pack["negative_test_summary"]
        lines.append("negative tests: %d/%d passed  (%s)"
                     % (s["passed"], s["executed"], ", ".join(s["ids"])))
        lines.append("chain integrity      : %s — %s"
                     % ("OK" if v["chain_integrity"]["ok"] else "FAILED",
                        v["chain_integrity"]["detail"]))
        lines.append("decision correlation : %s — %s"
                     % ("OK" if v["decision_correlation"]["ok"] else "FAILED",
                        v["decision_correlation"]["detail"]))
        return "\n".join(lines)
