import os
import unittest

from scripts import smoke_test


class SmokeTestScriptTests(unittest.TestCase):
    def test_default_env_sets_tokens(self):
        os.environ.pop("SAT_HMAC_SECRET", None)
        os.environ.pop("ORCHESTRATOR_INTERNAL_TOKEN", None)
        os.environ.pop("OPERATOR_TOKEN", None)
        os.environ.pop("SCOREBOARD_INTERNAL_TOKEN", None)

        env = smoke_test._default_env()

        self.assertIn("SAT_HMAC_SECRET", env)
        self.assertIn("ORCHESTRATOR_INTERNAL_TOKEN", env)
        self.assertIn("OPERATOR_TOKEN", env)
        self.assertIn("SCOREBOARD_INTERNAL_TOKEN", env)

    def test_compose_cmd_includes_files(self):
        cmd = smoke_test._compose_cmd(["up", "-d"])
        self.assertEqual(cmd[:6], ["docker", "compose", "-f", "compose.yml", "-f", "compose.staging.yml"])
        self.assertEqual(cmd[6:], ["up", "-d"])


if __name__ == "__main__":
    unittest.main()
