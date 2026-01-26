import asyncio
import base64
from datetime import UTC, datetime
import hmac
import json
import os
from pathlib import Path
import unittest


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def mint_sat(secret: str, claims: dict) -> str:
    header = {"alg": "HS256", "typ": "SAT"}
    header_encoded = b64url_encode(json.dumps(header).encode("utf-8"))
    payload_encoded = b64url_encode(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header_encoded}.{payload_encoded}".encode()
    signature = hmac.new(secret.encode("utf-8"), signing_input, "sha256").digest()
    return f"{header_encoded}.{payload_encoded}.{b64url_encode(signature)}"


def load_module():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    if "SAT_HMAC_SECRET" not in os.environ and "SAT_SECRET" not in os.environ:
        os.environ["SAT_HMAC_SECRET"] = "test-sat-secret"
    import importlib

    module = importlib.import_module("services.orchestrator.app.main")
    return importlib.reload(module)


class DummyMsg:
    def __init__(self, data: dict):
        self.data = json.dumps(data).encode("utf-8")
        self.acked = False
        self.nacked = False

    async def ack(self) -> None:
        self.acked = True

    async def nak(self) -> None:
        self.nacked = True


class MockState:
    """Mock app state for testing."""

    def __init__(self, module):
        self.replay_protector = module.ReplayProtector()
        self.scenarios = {}
        self.policy_evaluator = None


class MockApp:
    """Mock FastAPI app for testing."""

    def __init__(self, module):
        self.state = MockState(module)


class OrchestratorSatTests(unittest.TestCase):
    def _build_mock_app(self, module):
        """Build a minimal mock app for testing."""
        return MockApp(module)

    def test_sat_replay_rejected(self):
        module = load_module()
        app = self._build_mock_app(module)
        module.replay_protector = module.ReplayProtector()
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "jti": "jti-123",
            "exp": now + 300,
            "iat": now,
            "track": "netplus",
            "template_id": "netplus",
            "subject": "user-1",
            "tenant_id": "tenant-1",
            "tier": "free",
        }
        token = mint_sat(os.environ["SAT_HMAC_SECRET"], claims)
        asyncio.run(module.enforce_sat(app, token, "scn-1", "netplus", "netplus", "free"))
        with self.assertRaises(module.HTTPException):
            asyncio.run(module.enforce_sat(app, token, "scn-1", "netplus", "netplus", "free"))

    def test_spawn_request_denied_without_sat(self):
        module = load_module()
        module.scenarios.clear()
        msg = DummyMsg({"scenario_id": "scn-123", "track": "netplus", "request_id": "req-1"})
        asyncio.run(module.process_spawn_request(msg))
        self.assertTrue(msg.acked)
        self.assertEqual(module.scenarios, {})

    def test_opa_unavailable_denies_prelaunch(self):
        module = load_module()
        module.replay_protector = module.ReplayProtector()
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "jti": "jti-456",
            "exp": now + 300,
            "iat": now,
            "track": "netplus",
            "template_id": "netplus",
            "subject": "user-2",
            "tenant_id": "tenant-2",
            "tier": "pro",
            "scenario_id": "scn-opa",
        }
        token = mint_sat(os.environ["SAT_HMAC_SECRET"], claims)

        # Save original and mock the policy evaluator
        original_policy = getattr(module, "policy_evaluator", None)

        class DenyPolicy(module.PolicyEvaluator):
            async def allow(self, input_payload: dict):
                return False, "OPA unavailable"

        module.policy_evaluator = DenyPolicy()
        module.scenarios.clear()
        msg = DummyMsg(
            {
                "scenario_id": "scn-opa",
                "track": "netplus",
                "request_id": "req-2",
                "tier": "pro",
                "sat": token,
            }
        )
        try:
            asyncio.run(module.process_spawn_request(msg))
            self.assertTrue(msg.acked)
            self.assertEqual(module.scenarios, {})
        finally:
            if original_policy is not None:
                module.policy_evaluator = original_policy

    def test_sat_missing_tenant_or_subject_rejected(self):
        module = load_module()
        app = self._build_mock_app(module)
        module.replay_protector = module.ReplayProtector()
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "jti": "jti-missing",
            "exp": now + 300,
            "iat": now,
            "track": "netplus",
            "template_id": "netplus",
            "subject": "user-3",
            "tier": "free",
        }
        token = mint_sat(os.environ["SAT_HMAC_SECRET"], claims)
        with self.assertRaises(module.HTTPException):
            asyncio.run(module.enforce_sat(app, token, "scn-3", "netplus", "netplus", "free"))

    def test_sat_secret_alias_warning_emitted_once(self):
        os.environ.pop("SAT_HMAC_SECRET", None)
        os.environ["SAT_SECRET"] = "legacy-secret"
        module = load_module()
        with self.assertLogs("forge_orchestrator", level="WARNING") as logs:
            module._get_sat_secret()
            module._get_sat_secret()
        warnings = [record for record in logs.output if "SAT_SECRET is deprecated" in record]
        self.assertEqual(len(warnings), 1)

    def test_opa_payload_includes_entitlements(self):
        module = load_module()
        module.replay_protector = module.ReplayProtector()
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "jti": "jti-789",
            "exp": now + 300,
            "iat": now,
            "track": "netplus",
            "template_id": "netplus",
            "subject": "user-4",
            "tenant_id": "tenant-4",
            "tier": "team",
            "retention_days": 45,
            "scenario_id": "scn-entitlements",
        }
        token = mint_sat(os.environ["SAT_HMAC_SECRET"], claims)
        captured = {}

        # Save original and mock the policy evaluator
        original_policy = getattr(module, "policy_evaluator", None)

        class CapturePolicy(module.PolicyEvaluator):
            async def allow(self, input_payload: dict):
                captured.update(input_payload)
                return True, None

        module.policy_evaluator = CapturePolicy()
        module.scenarios.clear()
        msg = DummyMsg(
            {
                "scenario_id": "scn-entitlements",
                "track": "netplus",
                "request_id": "req-entitlements",
                "tier": "team",
                "sat": token,
            }
        )
        try:
            asyncio.run(module.process_spawn_request(msg))
            self.assertTrue(msg.acked)
            self.assertEqual(captured.get("plan"), "TEAM")
            self.assertEqual(captured.get("retention_days"), 45)
            self.assertEqual(captured.get("subject"), "user-4")
            self.assertEqual(captured.get("tenant_id"), "tenant-4")
        finally:
            if original_policy is not None:
                module.policy_evaluator = original_policy


if __name__ == "__main__":
    unittest.main()
