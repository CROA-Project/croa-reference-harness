"""Run all reference scenarios, print PASS/FAIL, write a sample C5 log, and verify the chain."""
import time
from .harness import Harness
from . import scenarios

def main():
    print("CROA Minimal Reference Harness — reference scenarios\n" + "-" * 60)
    passed = 0
    for fn in scenarios.ALL:
        name, ok, detail = fn()
        print(f"[{'PASS' if ok else 'FAIL'}] {name}\n        {detail}")
        passed += ok
    print("-" * 60)
    print(f"{passed}/{len(scenarios.ALL)} scenarios passed")

    # Produce a sample, verifiable C5 log from one governed session
    h = Harness(); now = time.time()
    h.governed_flow({"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}, now)
    action = {"subject_id": "cs-agent-01", "action_class": "data.export", "target": "billing"}
    h.governed_flow(action, now)  # denied
    h.present(None, now, "cs-agent-01")  # blocked, no CC
    ok, msg = h.c5.verify()
    h.c5.dump("c5_log.jsonl")
    print(f"\nSample C5 log written to c5_log.jsonl ({len(h.c5.events)} events)")
    print(f"Chain verification: {'OK' if ok else 'FAILED'} — {msg}")
    return 0 if passed == len(scenarios.ALL) and ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
