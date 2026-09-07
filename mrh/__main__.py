"""Run all reference scenarios, print PASS/FAIL, write a sample C5 log, and verify it."""
import time

from . import scenarios
from .harness import Harness


def main():
    print("CROA Minimal Reference Harness \u2014 reference scenarios\n" + "-" * 66)
    passed = 0
    for fn in scenarios.ALL:
        name, ok, detail = fn()
        print("[%s] %s\n        %s" % ("PASS" if ok else "FAIL", name, detail))
        passed += bool(ok)
    print("-" * 66)
    print("%d/%d scenarios passed" % (passed, len(scenarios.ALL)))

    # A sample, verifiable C5 record from one governed session.
    h = Harness()
    now = time.time()
    h.governed_flow({"subject_id": "cs-agent-01", "action_class": "data.read",
                     "target": "orders-db"}, now)
    h.governed_flow({"subject_id": "cs-agent-01", "action_class": "data.export",
                     "target": "billing"}, now)          # denied: unapproved destination
    h.present(None, now, "cs-agent-01",
              {"subject_id": "cs-agent-01", "action_class": "data.read",
               "target": "orders-db"})                    # blocked: no ECC
    ok, msg = h.c5.verify()
    h.c5.replicate()
    rec_ok, rec_msg = h.c5.reconcile()
    h.c5.dump("c5_log.jsonl")
    print("\nSample C5 log written to c5_log.jsonl (%d events)" % len(h.c5.events))
    print("Verification: %s \u2014 %s" % ("OK" if ok else "FAILED", msg))
    print("Replication:  %s \u2014 %s" % ("OK" if rec_ok else "FAILED", rec_msg))

    # Appendix Q Part 1: the pack an assessor is handed, extracted from a real run.
    from .nt_appendix_q import build_evidence_pack
    pack, _ = build_evidence_pack("evidence_pack.json")
    print("\nEvidence Pack written to evidence_pack.json")
    print(pack.summary())
    built = pack.build()
    pack_ok = (built["negative_test_summary"]["failed"] == 0
               and built["verification"]["chain_integrity"]["ok"]
               and built["verification"]["decision_correlation"]["ok"])
    return 0 if passed == len(scenarios.ALL) and ok and rec_ok and pack_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
