import unittest
from mrh import scenarios

class TestScenarios(unittest.TestCase):
    def test_all_scenarios_pass(self):
        for fn in scenarios.ALL:
            name, ok, detail = fn()
            self.assertTrue(ok, f"{name} failed: {detail}")

    def test_chain_verifies(self):
        import time
        from mrh.harness import Harness
        h = Harness()
        h.governed_flow({"subject_id": "a", "action_class": "data.read", "target": "orders-db"}, time.time())
        ok, msg = h.c5.verify()
        self.assertTrue(ok, msg)

if __name__ == "__main__":
    unittest.main()
