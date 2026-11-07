import unittest
import os
import sys
import tempfile
from io import StringIO
from unittest.mock import patch
from mrh import __version__
from mrh import cli

class TestCli(unittest.TestCase):
    def setUp(self):
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()

    def tearDown(self):
        sys.stdout = self.stdout
        sys.stderr = self.stderr

    def test_version(self):
        code = cli.main(["--version"])
        self.assertEqual(code, 0)
        self.assertEqual(sys.stdout.getvalue(), "croa " + __version__ + "\n")
        self.assertEqual(sys.stderr.getvalue(), "")

    def test_demo_default(self):
        code = cli.main(["demo"])
        self.assertEqual(code, 0)
        self.assertIn("CROA demo: permit", sys.stdout.getvalue())
        self.assertIn("[PASS] Positive path", sys.stdout.getvalue())

    def test_demo_permit(self):
        code = cli.main(["demo", "permit"])
        self.assertEqual(code, 0)
        self.assertIn("CROA demo: permit", sys.stdout.getvalue())
        self.assertIn("[PASS] Positive path", sys.stdout.getvalue())

    def test_demo_replay(self):
        code = cli.main(["demo", "replay"])
        self.assertEqual(code, 0)
        self.assertIn("CROA demo: replay", sys.stdout.getvalue())
        self.assertIn("[PASS] NT-003", sys.stdout.getvalue())

    def test_demo_deny(self):
        code = cli.main(["demo", "deny"])
        self.assertEqual(code, 0)
        self.assertIn("trajectory hard limit", sys.stdout.getvalue())
        self.assertIn("NT-006", sys.stdout.getvalue())

    @patch("mrh.scenarios.positive_path")
    def test_demo_failure_returns_exit_1(self, mock_scenario):
        mock_scenario.return_value = ("Mock Failure", False, "Simulated defect")
        code = cli.main(["demo", "permit"])
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] Mock Failure", sys.stdout.getvalue())

    def test_side_effects(self):
        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                os.chdir(tmpdir)
                for cmd in [["test"], ["demo"], ["demo", "permit"], ["demo", "deny"], ["demo", "replay"]]:
                    code = cli.main(cmd)
                    self.assertEqual(code, 0, f"Command {cmd} failed")
                    self.assertFalse(os.path.exists("c5_log.jsonl"), f"Command {cmd} created c5_log.jsonl")
                    self.assertFalse(os.path.exists("evidence_pack.json"), f"Command {cmd} created evidence_pack.json")
            finally:
                os.chdir(original_cwd)

    def test_invalid_command(self):
        code = cli.main(["invalid"])
        self.assertEqual(code, 2)

    def test_invalid_demo(self):
        code = cli.main(["demo", "invalid"])
        self.assertEqual(code, 2)

    def test_no_command(self):
        code = cli.main([])
        self.assertEqual(code, 2)
