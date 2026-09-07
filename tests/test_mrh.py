import hashlib
import hmac
import os
import tempfile
import threading
import time
import unittest

from mrh import scenarios
from mrh.components import _ECC_KEY, AuthorizationInvalid, ExecutionFirewall, _canon
from mrh.harness import Harness
from mrh.redemption import InProcessRegistry
from mrh.wal import LocalSigner

READ = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "crm"}
EXPORT = {"subject_id": "cs-agent-01", "action_class": "data.export", "target": "billing"}


def permit(h, action, sid="cs-agent-01"):
    return h.c5.emit("PERMIT", "C2", sid, **{
        "event.action_spec": action, "event.decision_basis": "PERMIT"})["event.id"]


class TestScenarios(unittest.TestCase):
    def test_all_scenarios_pass(self):
        for fn in scenarios.ALL:
            name, ok, detail = fn()
            self.assertTrue(ok, "%s failed: %s" % (name, detail))

    def test_chain_verifies(self):
        h = Harness()
        h.governed_flow(dict(READ, target="orders-db"), time.time())
        ok, msg = h.c5.verify()
        self.assertTrue(ok, msg)


class TestRedemptionRegistry(unittest.TestCase):
    """Part II §4.8. The requirements that make single-use hold under concurrency.

    §4.8 is explicit that a query-then-act check is non-conformant and that the registry
    must be shared across every C6 instance. Each test below fails on an implementation
    that gets either half wrong.
    """

    def setUp(self):
        self.now = time.time()

    def test_claim_is_atomic_over_the_whole_key_set(self):
        reg = InProcessRegistry()
        reg.claim({"auth": "auth-1"})
        r = reg.claim({"ecc": "ecc-1", "auth": "auth-1"})
        self.assertFalse(r.granted)
        self.assertEqual(r.conflict, "auth")
        self.assertFalse(reg.is_spent("ecc-1"),
                         "a refused claim must not have taken the other key")

    def test_concurrent_redemption_admits_exactly_one(self):
        """100 threads present one ECC. The registry must grant once."""
        h = Harness()
        pid = permit(h, READ)
        ecc = h.c7.compile(READ, self.now, permit_event_id=pid)
        admitted, lock = [], threading.Lock()

        def attempt():
            status, _, _ = h.c6.redeem(ecc, self.now, "cs-agent-01", READ)
            if status == "AUTHORIZED":
                with lock:
                    admitted.append(status)

        threads = [threading.Thread(target=attempt) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(admitted), 1,
                         "%d concurrent redemptions admitted" % len(admitted))

    def test_concurrent_authorization_admits_exactly_one(self):
        """100 threads present 100 distinct ECCs sharing one authorization."""
        h = Harness()
        auth = h.c1.issue_authorization(EXPORT, self.now)
        eccs = [h.c7.compile(EXPORT, self.now, permit_event_id=permit(h, EXPORT),
                             authorization=auth) for _ in range(100)]
        admitted, lock = [], threading.Lock()

        def attempt(ecc):
            status, _, _ = h.c6.redeem(ecc, self.now, "cs-agent-01", EXPORT)
            if status == "AUTHORIZED":
                with lock:
                    admitted.append(ecc["ecc.id"])

        threads = [threading.Thread(target=attempt, args=(e,)) for e in eccs]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(admitted), 1,
                         "one single-use authorization backed %d executions" % len(admitted))

    def test_firewall_holds_no_redemption_state(self):
        """§4.8: a per-instance redemption record is non-conformant. The firewall must
        carry none, so that sharing a registry is the only way to construct it."""
        fw = ExecutionFirewall(InProcessRegistry())
        leaked = [a for a in vars(fw) if "redeem" in a.lower() or "spent" in a.lower()]
        self.assertEqual(leaked, [], "firewall keeps local redemption state: %s" % leaked)

    def test_two_instances_one_registry_admit_once(self):
        h = Harness(firewalls=2)
        pid = permit(h, READ)
        ecc = h.c7.compile(READ, self.now, permit_event_id=pid)
        scenarios._record_compiled(h, ecc, pid)
        a = h.present(ecc, self.now, "cs-agent-01", READ, firewall=h.firewalls[0])
        b = h.present(ecc, self.now, "cs-agent-01", READ, firewall=h.firewalls[1])
        self.assertTrue(a["admitted"])
        self.assertFalse(b["admitted"])
        self.assertEqual(b["block_reason"], "ECC_ALREADY_REDEEMED")

    def test_two_instances_two_registries_is_the_defect(self):
        """The negative control. With a registry each -- the pre-v1.0.1 shape -- the
        same ECC is admitted twice and the governed system takes two effects. If this
        test ever fails, the test above has stopped proving anything."""
        h = Harness()
        h.firewalls = [ExecutionFirewall(InProcessRegistry(), "c6-1"),
                       ExecutionFirewall(InProcessRegistry(), "c6-2")]
        h.c6 = h.firewalls[0]
        pid = permit(h, READ)
        ecc = h.c7.compile(READ, self.now, permit_event_id=pid)
        scenarios._record_compiled(h, ecc, pid)
        h.present(ecc, self.now, "cs-agent-01", READ, firewall=h.firewalls[0])
        h.present(ecc, self.now, "cs-agent-01", READ, firewall=h.firewalls[1])
        self.assertEqual(len(h.applied("crm")), 2)
        ok, msg = h.c5.verify()
        self.assertFalse(ok, "C5 correlation must catch the double authorization")

    def test_static_failure_does_not_consume_the_single_use(self):
        """An ECC refused on expiry, subject or scope must remain unredeemed: the
        static checks run before the claim, so a refusal costs nothing."""
        h = Harness()
        pid = permit(h, READ)
        ecc = h.c7.compile(READ, self.now, permit_event_id=pid, ttl=1)
        h.present(ecc, self.now + 60, "cs-agent-01", READ)
        self.assertFalse(h.registry.is_spent(ecc["ecc.id"]))

    @unittest.skipUnless(hasattr(os, "fork"), "needs os.fork")
    def test_file_lock_registry_is_linearizable_across_processes(self):
        name, ok, detail = scenarios.registry_cross_process_cas()
        self.assertTrue(ok, detail)


class TestEvidencePath(unittest.TestCase):
    """Appendix R. The local write-ahead log and the asynchronous replication tail."""

    def test_wal_write_is_durable(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "c5.wal")
        from mrh.audit import AuditStore
        h = Harness(audit=AuditStore(path=path))
        h.governed_flow(dict(READ, target="orders-db"), time.time())
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(sum(1 for _ in fh), len(h.c5.events))

    def test_signature_covers_the_chain_hash(self):
        """R.3 step 4. Re-chaining an event without re-signing must not verify."""
        h = Harness()
        h.governed_flow(dict(READ, target="orders-db"), time.time())
        h.c5.events[1]["event.chain_hash"] = "0" * 64
        ok, _ = h.c5.verify_chain()
        self.assertFalse(ok)

    def test_replication_is_not_the_gate(self):
        """R.5. Events are admitted and valid before replication; an unreplicated
        event is a full-status evidence record, not a provisional one."""
        h = Harness()
        h.governed_flow(dict(READ, target="orders-db"), time.time())
        self.assertGreater(h.c5.replicator.lag(), 0)
        ok, _ = h.c5.verify()
        self.assertTrue(ok, "unreplicated events must verify on the local WAL alone")

    def test_central_store_rejects_a_gap(self):
        h = Harness()
        h.governed_flow(dict(READ, target="orders-db"), time.time())
        batch = h.c5.events[1:]                 # drop the first: a gap
        ok, msg = h.c5.central.receive(batch)
        self.assertFalse(ok)
        self.assertTrue(h.c5.central.alerts)

    def test_local_and_central_must_agree(self):
        """R.4 invariant 7."""
        h = Harness()
        h.governed_flow(dict(READ, target="orders-db"), time.time())
        h.c5.replicate()
        ok, msg = h.c5.reconcile()
        self.assertTrue(ok, msg)

    def test_replication_lag_is_a_monitored_parameter(self):
        """R.4 invariant 5: a breach of the declared maximum raises an alert."""
        h = Harness()
        h.c5.replicator.max_lag = 1
        for _ in range(3):
            h.governed_flow(dict(READ, target="orders-db"), time.time())
        ok, msg = h.c5.replicator.check_lag()
        self.assertFalse(ok)
        self.assertTrue(h.c5.replicator.alerts)

    def test_signing_key_is_not_reachable(self):
        """R.4 invariant 4: the WAL signing key must not sit in the agent's reach."""
        signer = LocalSigner()
        self.assertFalse(hasattr(signer, "key"))
        self.assertEqual([a for a in vars(signer) if "key" in a.lower() and "__" not in a], [])


class TestAdversarial(unittest.TestCase):
    """The scenarios that would have caught H-01 to H-04. Kept as explicit methods, not
    only as scenario functions, so a failure names the defect it lets back in."""

    def setUp(self):
        self.h = Harness()
        self.now = time.time()

    # -------------------------------------------------------------- H-01
    def test_h01_authorization_backs_one_execution(self):
        """The guarantee moved from C7 to C6 in v1.0.1 -- §4.8 puts redemption at the
        boundary, and §4.8 explicitly anticipates a second ECC being compiled against a
        spent authorization. Two ECCs may exist; only one may be admitted."""
        auth = self.h.c1.issue_authorization(EXPORT, self.now)
        e1 = self.h.c7.compile(EXPORT, self.now, permit_event_id=permit(self.h, EXPORT),
                               authorization=auth)
        e2 = self.h.c7.compile(EXPORT, self.now, permit_event_id=permit(self.h, EXPORT),
                               authorization=auth)
        self.assertNotEqual(e1["ecc.id"], e2["ecc.id"])
        self.assertEqual(e1["ecc.auth_ref"], auth["auth_id"])
        s1, _, _ = self.h.c6.redeem(e1, self.now, "cs-agent-01", EXPORT)
        s2, r2, _ = self.h.c6.redeem(e2, self.now, "cs-agent-01", EXPORT)
        self.assertEqual(s1, "AUTHORIZED")
        self.assertEqual(s2, "BLOCKED")
        self.assertEqual(r2, "AUTHORIZATION_ALREADY_REDEEMED")

    def test_h01_governed_flow_reuse_is_refused(self):
        auth = self.h.c1.issue_authorization(EXPORT, self.now)
        first = self.h.governed_flow(EXPORT, self.now, authorization=auth)
        second = self.h.governed_flow(EXPORT, self.now, authorization=auth)
        self.assertTrue(first["admitted"])
        self.assertFalse(second.get("admitted", False))
        n = sum(1 for e in self.h.c5.events if e["event.type"] == "EXECUTION_AUTHORIZED")
        self.assertEqual(n, 1)
        self.assertEqual(len(self.h.applied("billing")), 1)

    def test_expired_authorization_never_compiles(self):
        auth = self.h.c1.issue_authorization(EXPORT, self.now, ttl=1)
        with self.assertRaises(AuthorizationInvalid):
            self.h.c7.compile(EXPORT, self.now + 60,
                              permit_event_id=permit(self.h, EXPORT), authorization=auth)

    # -------------------------------------------------------------- H-02
    def test_h02_subject_substitution_blocked(self):
        action = dict(READ, subject_id="subject-A")
        ecc = self.h.c7.compile(action, self.now,
                                permit_event_id=permit(self.h, action, "subject-A"))
        r = self.h.present(ecc, self.now, "subject-B", action)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_detail"], "SUBJECT_MISMATCH")
        self.assertFalse(any(e["event.type"] == "EXECUTION_AUTHORIZED"
                             and e["event.subject_id"] == "subject-B"
                             for e in self.h.c5.events))

    def test_h02_operation_mutation_blocked(self):
        ecc = self.h.c7.compile(READ, self.now, permit_event_id=permit(self.h, READ))
        r = self.h.present(ecc, self.now, "cs-agent-01", dict(READ, target="billing"))
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_detail"], "OPERATION_OUTSIDE_AUTHORIZATION_SCOPE")

    # -------------------------------------------------------------- H-03
    def test_h03_ecc_id_is_content_address(self):
        ecc = self.h.c7.compile(READ, self.now, permit_event_id=permit(self.h, READ))
        content = dict((k, v) for k, v in ecc.items()
                       if k not in ("ecc.id", "ecc.signature"))
        expected = "ecc-" + hashlib.sha256(_canon(content).encode()).hexdigest()
        self.assertEqual(ecc["ecc.id"], expected)

    def test_h03_same_inputs_same_id(self):
        pid = permit(self.h, READ)
        a = self.h.c7.compile(READ, self.now, permit_event_id=pid)
        b = self.h.c7.compile(READ, self.now, permit_event_id=pid)
        self.assertEqual(a["ecc.id"], b["ecc.id"])

    def test_h03_forged_id_refused(self):
        """The forged ECC is re-signed, so the signature check passes and the
        content-address check is the one that must fire. Without the re-signing this
        test would pass on the signature branch and leave the address check dead."""
        ecc = dict(self.h.c7.compile(READ, self.now, permit_event_id=permit(self.h, READ)))
        ecc["ecc.id"] = "ecc-" + "0" * 64
        ecc["ecc.signature"] = hmac.new(
            _ECC_KEY,
            _canon(dict((k, v) for k, v in ecc.items() if k != "ecc.signature")).encode(),
            hashlib.sha256).hexdigest()
        r = self.h.present(ecc, self.now, "cs-agent-01", READ)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_detail"], "ID_NOT_CONTENT_ADDRESSED",
                         "the content-address check must be the branch that fires")

    def test_forged_signature_refused(self):
        ecc = dict(self.h.c7.compile(READ, self.now, permit_event_id=permit(self.h, READ)))
        ecc["ecc.signature"] = "0" * 64
        r = self.h.present(ecc, self.now, "cs-agent-01", READ)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_detail"], "SIGNATURE_INVALID")

    def test_stale_invariant_set_refused(self):
        """§4.8: C6 verifies the ECC's invariant-set version against the current
        registry and refuses a contract compiled under a superseded one."""
        ecc = self.h.c7.compile(READ, self.now, permit_event_id=permit(self.h, READ))
        self.h.c1.invariant_set_version = "inv-2026-10-01"     # registry moved on
        r = self.h.present(ecc, self.now, "cs-agent-01", READ)
        self.assertFalse(r["admitted"])
        self.assertEqual(r["block_reason"], "ECC_INVARIANT_STALE")

    # -------------------------------------------------------------- H-04
    def test_h04_double_authorization_fails_verification(self):
        name, ok, detail = scenarios.h04_double_authorization_detected()
        self.assertTrue(ok, detail)

    def test_h04_orphan_execution_fails_verification(self):
        name, ok, detail = scenarios.h04b_orphan_execution_detected()
        self.assertTrue(ok, detail)

    def test_h04_tampered_event_fails_chain(self):
        h = Harness()
        h.governed_flow(dict(READ, target="orders-db"), self.now)
        h.c5.events[0]["event.subject_id"] = "b"
        ok, _ = h.c5.verify()
        self.assertFalse(ok, "tampering with a recorded event must break verification")

    def test_h04_deleted_event_fails_chain(self):
        h = Harness()
        h.governed_flow(dict(READ, target="orders-db"), self.now)
        del h.c5.events[1]
        ok, _ = h.c5.verify()
        self.assertFalse(ok, "deleting a recorded event must break verification")


class TestEventSchemaConformance(unittest.TestCase):
    """Every event the harness emits must validate against the published
    event.schema.json.

    This is the join between the specification repository and this one: the schema says
    what a v1.0.1 governance event is, and the harness is the thing that has to produce
    one. Skipped when the schema or jsonschema is absent, so the suite still runs
    standalone; in CI both repositories are checked out and this is the test that catches
    a field renamed on one side only.

    Point it at a checkout with CROA_SCHEMA_DIR, or leave a sibling CROA/ clone.
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

    def test_every_emitted_event_validates(self):
        h = Harness(firewalls=2)
        now = time.time()
        h.governed_flow(dict(READ, target="orders-db"), now)           # permit path
        h.governed_flow(EXPORT, now)                                   # deny path
        h.governed_flow(dict(READ, target="shadow-db"), now)           # context failure
        h.present(None, now, "cs-agent-01", READ)                      # blocked, no ECC
        auth = h.c1.issue_authorization(EXPORT, now)
        h.governed_flow(EXPORT, now, authorization=auth)               # governed exception
        h.governed_flow(EXPORT, now, authorization=auth)               # refused reuse

        self.assertGreater(len(h.c5.events), 10)
        seen = set()
        for ev in h.c5.events:
            seen.add(ev["event.type"])
            errors = sorted(self.validator.iter_errors(ev), key=str)
            self.assertEqual(
                [e.message for e in errors], [],
                "%s does not validate against event.schema.json" % ev["event.type"])
        for required in ("PERMIT", "DENY", "ECC_COMPILED", "EXECUTION_AUTHORIZED",
                         "EXECUTION_BLOCKED", "CONTEXT_FAILURE", "EXECUTION_COMPLETED",
                         "EFFECT_ATTESTED"):
            self.assertIn(required, seen)


if __name__ == "__main__":
    unittest.main()
