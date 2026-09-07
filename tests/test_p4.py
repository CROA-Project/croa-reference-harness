"""H-06 — property P4 asserted on an external effect.

Every assertion in this file is on the governed system's **own log file**, written by a
different OS process that this test cannot reach. None of them is on a return value.
That is the whole difference between this file and the NT-001 that has stood in the
suite since the beginning: the old one showed that a Python function returned the string
`BLOCKED`, which is a fact about the harness rather than about the governed system.

Skipped on platforms without `AF_UNIX` and `socketpair` (Windows), because the bench's
unreachability comes from not naming a socket, and that construction is POSIX.
"""
import errno
import os
import socket
import time
import unittest

from mrh.harness import Harness
from mrh.p4 import P4Bench

READ = {"subject_id": "cs-agent-01", "action_class": "data.read", "target": "orders-db"}
OPERATION = {"action_class": "data.read", "target": "orders-db"}


def _supported():
    return hasattr(socket, "AF_UNIX") and hasattr(socket, "socketpair")


@unittest.skipUnless(_supported(), "P4 bench needs AF_UNIX and socketpair (POSIX)")
class TestP4Boundary(unittest.TestCase):

    def setUp(self):
        self.h = Harness()
        self.now = time.time()
        self.bench = P4Bench().start()
        self.addCleanup(self.bench.stop)

    def _ecc(self, subject="cs-agent-01", action=None, ttl=300):
        action = action or READ
        gga = self.h.c3.ground(action, self.now)
        pid = self.h.c5.emit("PERMIT", "C2", subject,
                             **{"event.session_id": "sess-p4"})["event.id"]
        return self.h.c7.compile(gga, subject, self.now, permit_event_id=pid, ttl=ttl)

    # ------------------------------------------------------------------ the two paths
    def test_direct_path_fails_in_the_kernel(self):
        """NT-001, restated as the property it is supposed to test.

        The agent asks the operating system to connect to where a governed system would
        conventionally listen. There is no such address, so `connect(2)` fails before any
        code of ours runs. An assertion on errno is an assertion about the system; an
        assertion on a boolean returned by the thing being tested is not.
        """
        self.assertEqual(self.bench.direct_attempt(), errno.ENOENT)
        self.assertFalse(os.path.exists(self.bench.system_path),
                         "the governed system must not be bound to any path")
        self.assertEqual(self.bench.system_log(), [],
                         "a failed direct attempt must leave no effect")

    def test_the_governed_system_listens_on_no_port(self):
        """A reader is entitled to suspect a quiet loopback listener. Ten ephemeral
        ports is not a proof of absence and is not offered as one -- the proof is that
        `run_governed_system` contains no `bind` call. This is corroboration."""
        for port in range(49200, 49210):
            self.assertIn(self.bench.direct_attempt_tcp(port),
                          (errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH))
        self.assertEqual(self.bench.system_log(), [])

    def test_governed_path_produces_the_effect(self):
        reply = self.bench.through_gateway(self._ecc(), "cs-agent-01")
        self.assertTrue(reply["admitted"])
        log = self.bench.system_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["action_class"], "data.read")
        self.assertEqual(log[0]["target"], "orders-db")

    # ------------------------------------------- refusals are observably not silent
    def test_no_ecc_no_effect(self):
        reply = self.bench.through_gateway(None, "cs-agent-01", OPERATION)
        self.assertFalse(reply["admitted"])
        self.assertEqual(reply["block_reason"], "ECC_NOT_FOUND")
        self.assertEqual(self.bench.system_log(), [])

    def test_replay_reaches_the_system_once(self):
        """NT-003 with an external effect. The second presentation is refused, and the
        evidence is that the governed system performed the operation once -- not that a
        function said so."""
        ecc = self._ecc()
        self.assertTrue(self.bench.through_gateway(ecc, "cs-agent-01")["admitted"])
        second = self.bench.through_gateway(ecc, "cs-agent-01")
        self.assertFalse(second["admitted"])
        self.assertEqual(second["block_reason"], "ECC_ALREADY_REDEEMED")
        self.assertEqual(len(self.bench.system_log()), 1)

    def test_subject_substitution_reaches_nothing(self):
        """H-02 at the boundary, observed from the far side of it."""
        ecc = self._ecc()
        reply = self.bench.through_gateway(ecc, "attacker-01")
        self.assertFalse(reply["admitted"])
        self.assertEqual(reply["block_detail"], "SUBJECT_MISMATCH")
        self.assertEqual(self.bench.system_log(), [])

    def test_operation_outside_scope_reaches_nothing(self):
        ecc = self._ecc()
        reply = self.bench.through_gateway(
            ecc, "cs-agent-01", {"action_class": "data.export", "target": "analytics"})
        self.assertFalse(reply["admitted"])
        self.assertEqual(reply["block_detail"], "OPERATION_OUTSIDE_AUTHORIZATION_SCOPE")
        self.assertEqual(self.bench.system_log(), [])

    def test_expired_ecc_reaches_nothing(self):
        ecc = self._ecc(ttl=-1)
        reply = self.bench.through_gateway(ecc, "cs-agent-01")
        self.assertFalse(reply["admitted"])
        self.assertEqual(reply["block_reason"], "ECC_EXPIRED")
        self.assertEqual(self.bench.system_log(), [])

    # ------------------------------------------------------------------- the invariant
    def test_every_effect_was_admitted_first(self):
        """The property, stated once over a mixed run: the number of entries in the
        governed system's log equals the number of admissions, and refusals contribute
        nothing. Six attempts, one of which is legitimate."""
        admitted = 0
        attempts = [
            (None, "cs-agent-01", OPERATION),
            (self._ecc(), "attacker-01", None),
            (self._ecc(ttl=-1), "cs-agent-01", None),
            (self._ecc(), "cs-agent-01",
             {"action_class": "data.export", "target": "analytics"}),
            (self._ecc(), "cs-agent-01", None),
        ]
        for ecc, subject, op in attempts:
            if self.bench.through_gateway(ecc, subject, op)["admitted"]:
                admitted += 1
        self.assertEqual(admitted, 1)
        self.assertEqual(len(self.bench.system_log()), admitted)


if __name__ == "__main__":
    unittest.main()
