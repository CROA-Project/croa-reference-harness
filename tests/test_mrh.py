import time
import unittest

from mrh import scenarios
from mrh.components import AuthorizationSpent
from mrh.harness import Harness


class TestScenarios(unittest.TestCase):
    def test_all_scenarios_pass(self):
        for fn in scenarios.ALL:
            name, ok, detail = fn()
            self.assertTrue(ok, f"{name} failed: {detail}")

    def test_chain_verifies(self):
        h = Harness()
        h.governed_flow(
            {"subject_id": "a", "action_class": "data.read", "target": "orders-db"}, time.time())
        ok, msg = h.c5.verify()
        self.assertTrue(ok, msg)


class TestAdversarial(unittest.TestCase):
    """The scenarios that would have caught H-01 to H-04. Kept as explicit test methods,
    not only as scenario functions, so a failure names the defect it lets back in."""

    def setUp(self):
        self.h = Harness()
        self.now = time.time()
        self.action = {"subject_id": "cs-agent-01",
                       "action_class": "data.export", "target": "billing"}

    # -------------------------------------------------------------- H-01
    def test_h01_authorization_cannot_back_two_commitments(self):
        auth = self.h.c1.issue_authorization(self.action, self.now)
        p1 = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                            **{"event.action_spec": self.action})["event.id"]
        p2 = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                            **{"event.action_spec": self.action})["event.id"]
        self.h.c7.compile(self.action, self.now, permit_event_id=p1, authorization=auth)
        with self.assertRaises(AuthorizationSpent):
            self.h.c7.compile(self.action, self.now, permit_event_id=p2, authorization=auth)

    def test_h01_governed_flow_reuse_is_denied(self):
        auth = self.h.c1.issue_authorization(self.action, self.now)
        first = self.h.governed_flow(self.action, self.now, authorization=auth)
        second = self.h.governed_flow(self.action, self.now, authorization=auth)
        self.assertTrue(first["admitted"])
        self.assertEqual(second["outcome"], "DENIED")
        n = sum(1 for e in self.h.c5.events if e["event.type"] == "EXECUTION_AUTHORIZED")
        self.assertEqual(n, 1)

    def test_h01_concurrent_reservation_admits_one(self):
        """N threads race to reserve the same authorization. Exactly one must win."""
        import threading
        auth = self.h.c1.issue_authorization(self.action, self.now)
        won, lock = [], threading.Lock()

        def attempt():
            try:
                aid = self.h.c1.reserve_authorization(auth, self.action, self.now)
                with lock:
                    won.append(aid)
            except AuthorizationSpent:
                pass

        threads = [threading.Thread(target=attempt) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(won), 1, f"{len(won)} threads reserved the same authorization")

    def test_h01_concurrent_redemption_admits_one(self):
        """N threads present the same commitment at C6. Exactly one must be admitted."""
        import threading
        action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
        pid = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                             **{"event.action_spec": action})["event.id"]
        cc = self.h.c7.compile(action, self.now, permit_event_id=pid)
        admitted, lock = [], threading.Lock()

        def attempt():
            status, _ = self.h.c6.redeem(cc, self.now, "cs-agent-01", action)
            if status == "AUTHORIZED":
                with lock:
                    admitted.append(status)

        threads = [threading.Thread(target=attempt) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(admitted), 1, f"{len(admitted)} concurrent redemptions admitted")

    # -------------------------------------------------------------- H-02
    def test_h02_subject_substitution_blocked(self):
        action = {"subject_id": "subject-A", "action_class": "data.read", "target": "crm"}
        pid = self.h.c5.emit("PERMIT", "C2", "subject-A",
                             **{"event.action_spec": action})["event.id"]
        cc = self.h.c7.compile(action, self.now, permit_event_id=pid)
        r = self.h.present(cc, self.now, "subject-B", action)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_reason"], "CC_SUBJECT_MISMATCH")
        self.assertFalse(any(e["event.type"] == "EXECUTION_AUTHORIZED"
                             and e["event.subject_id"] == "subject-B"
                             for e in self.h.c5.events))

    def test_h02_operation_mutation_blocked(self):
        action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
        mutated = dict(action, target="billing")
        pid = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                             **{"event.action_spec": action})["event.id"]
        cc = self.h.c7.compile(action, self.now, permit_event_id=pid)
        r = self.h.present(cc, self.now, "cs-agent-01", mutated)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_reason"], "CC_OPERATION_MISMATCH")

    # -------------------------------------------------------------- H-03
    def test_h03_cc_id_is_content_address(self):
        import hashlib
        import json
        action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
        pid = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                             **{"event.action_spec": action})["event.id"]
        cc = self.h.c7.compile(action, self.now, permit_event_id=pid)
        content = {k: v for k, v in cc.items() if k not in ("cc.id", "signature")}
        expected = "cc-" + hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(cc["cc.id"], expected)

    def test_h03_same_inputs_same_id(self):
        action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
        pid = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                             **{"event.action_spec": action})["event.id"]
        a = self.h.c7.compile(action, self.now, permit_event_id=pid)
        b = self.h.c7.compile(action, self.now, permit_event_id=pid)
        self.assertEqual(a["cc.id"], b["cc.id"])

    def test_h03_forged_id_refused(self):
        """The forged commitment is re-signed, so the signature check passes and the
        content-address check is the one that must fire. Without the re-signing this
        test would pass on CC_SIGNATURE_INVALID and leave _id_ok() as dead code."""
        import hashlib
        import hmac

        from mrh.components import _CC_KEY, _canon

        action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
        pid = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                             **{"event.action_spec": action})["event.id"]
        cc = dict(self.h.c7.compile(action, self.now, permit_event_id=pid))
        cc["cc.id"] = "cc-" + "0" * 64
        cc["signature"] = hmac.new(
            _CC_KEY, _canon({k: v for k, v in cc.items() if k != "signature"}).encode(),
            hashlib.sha256,
        ).hexdigest()
        r = self.h.present(cc, self.now, "cs-agent-01", action)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_reason"], "CC_ID_NOT_CONTENT_ADDRESSED",
                         "the content-address check must be the branch that fires")

    def test_forged_signature_refused(self):
        action = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
        pid = self.h.c5.emit("PERMIT", "C2", "cs-agent-01",
                             **{"event.action_spec": action})["event.id"]
        cc = dict(self.h.c7.compile(action, self.now, permit_event_id=pid))
        cc["signature"] = "0" * 64
        r = self.h.present(cc, self.now, "cs-agent-01", action)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_reason"], "CC_SIGNATURE_INVALID")

    # -------------------------------------------------------------- H-04
    def test_h04_double_authorization_fails_verification(self):
        name, ok, detail = scenarios.h04_double_authorization_detected()
        self.assertTrue(ok, detail)

    def test_h04_orphan_execution_fails_verification(self):
        name, ok, detail = scenarios.h04b_orphan_execution_detected()
        self.assertTrue(ok, detail)

    def test_h04_tampered_event_fails_chain(self):
        h = Harness()
        h.governed_flow({"subject_id": "a", "action_class": "data.read",
                         "target": "orders-db"}, self.now)
        h.c5.events[0]["event.subject_id"] = "b"
        ok, msg = h.c5.verify()
        self.assertFalse(ok, "tampering with a recorded event must break verification")

    def test_h04_deleted_event_fails_chain(self):
        h = Harness()
        h.governed_flow({"subject_id": "a", "action_class": "data.read",
                         "target": "orders-db"}, self.now)
        del h.c5.events[1]
        ok, msg = h.c5.verify()
        self.assertFalse(ok, "deleting a recorded event must break verification")


if __name__ == "__main__":
    unittest.main()
