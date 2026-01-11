import asyncio
import base64
import hmac
import json
import os
import sys
import unittest
import uuid
import importlib.util
from datetime import datetime, timezone
from pathlib import Path


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def mint_sat(secret: str, claims: dict) -> str:
    header = {"alg": "HS256", "typ": "SAT"}
    header_encoded = b64url_encode(json.dumps(header).encode("utf-8"))
    payload_encoded = b64url_encode(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing_input, "sha256").digest()
    return f"{header_encoded}.{payload_encoded}.{b64url_encode(signature)}"


def load_module():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    os.environ["SAT_SECRET"] = "test-sat-secret"

    module_path = Path(__file__).resolve().parents[1] / "app" / "main.py"
    module_name = f"orchestrator_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    if spec.loader is None:
        raise RuntimeError("Failed to load orchestrator module")
    spec.loader.exec_module(module)
    return module


class DummyMsg:
    def __init__(self, data: dict):
        self.data = json.dumps(data).encode("utf-8")
        self.acked = False
        self.nacked = False

    async def ack(self) -> None:
        self.acked = True

    async def nak(self) -> None:
        self.nacked = True


class OrchestratorSatTests(unittest.TestCase):
    def test_sat_replay_rejected(self):
        module = load_module()
        module.replay_protector = module.ReplayProtector()
        now = int(datetime.now(timezone.utc).timestamp())
        claims = {
            "jti": "jti-123",
            "exp": now + 300,
            "iat": now,
            "track": "netplus",
            "template_id": "netplus",
            "subject": "user-1",
            "tier": "free",
        }
        token = mint_sat(os.environ["SAT_SECRET"], claims)
        asyncio.run(module.enforce_sat(token, "scn-1", "netplus", "netplus"))
        with self.assertRaises(module.HTTPException):
            asyncio.run(module.enforce_sat(token, "scn-1", "netplus", "netplus"))

    def test_spawn_request_denied_without_sat(self):
        module = load_module()
        module.scenarios.clear()
        msg = DummyMsg(
            {"scenario_id": "scn-123", "track": "netplus", "request_id": "req-1"}
        )
        asyncio.run(module.process_spawn_request(msg))
        self.assertTrue(msg.acked)
        self.assertEqual(module.scenarios, {})

    def test_opa_unavailable_denies_prelaunch(self):
        module = load_module()
        module.replay_protector = module.ReplayProtector()
        now = int(datetime.now(timezone.utc).timestamp())
        claims = {
            "jti": "jti-456",
            "exp": now + 300,
            "iat": now,
            "track": "netplus",
            "template_id": "netplus",
            "subject": "user-2",
            "tier": "pro",
            "scenario_id": "scn-opa",
        }
        token = mint_sat(os.environ["SAT_SECRET"], claims)

        async def deny_policy(_template: dict):
            return False, "OPA unavailable"

        module.check_opa_policy = deny_policy
        module.scenarios.clear()
        msg = DummyMsg(
            {
                "scenario_id": "scn-opa",
                "track": "netplus",
                "request_id": "req-2",
                "sat": token,
            }
        )
        asyncio.run(module.process_spawn_request(msg))
        self.assertTrue(msg.acked)
        self.assertEqual(module.scenarios, {})


if __name__ == "__main__":
    unittest.main()
