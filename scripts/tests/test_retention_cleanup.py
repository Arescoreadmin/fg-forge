from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import tempfile
import unittest

from scripts import retention_cleanup


class RetentionCleanupTests(unittest.TestCase):
    def setUp(self):
        self.original_token = os.environ.get("OPERATOR_TOKEN")
        os.environ["OPERATOR_TOKEN"] = "test-token"

    def tearDown(self):
        if self.original_token is None:
            os.environ.pop("OPERATOR_TOKEN", None)
        else:
            os.environ["OPERATOR_TOKEN"] = self.original_token

    def test_find_expired_results_skips_investigation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            scenario_dir = root / "scenarios" / "scn-1"
            results_dir = scenario_dir / "results"
            results_dir.mkdir(parents=True)
            (scenario_dir / retention_cleanup.INVESTIGATION_FLAG).write_text(
                "active", encoding="utf-8"
            )
            past = datetime.now(UTC) - timedelta(days=40)
            os.utime(results_dir, (past.timestamp(), past.timestamp()))
            targets = retention_cleanup.find_expired_results(root, 30)
            self.assertEqual(targets, [])

    def test_perform_cleanup_dry_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            scenario_dir = root / "scenarios" / "scn-2"
            results_dir = scenario_dir / "results"
            results_dir.mkdir(parents=True)
            past = datetime.now(UTC) - timedelta(days=40)
            os.utime(results_dir, (past.timestamp(), past.timestamp()))
            targets = retention_cleanup.find_expired_results(root, 30)
            logs = retention_cleanup.perform_cleanup(targets, dry_run=True)
            self.assertTrue(results_dir.exists())
            self.assertEqual(len(logs), 1)
            self.assertIn("DRY-RUN delete", logs[0])

    def test_require_operator_token(self):
        with self.assertRaises(PermissionError):
            retention_cleanup._require_operator_token("wrong")


if __name__ == "__main__":
    unittest.main()
