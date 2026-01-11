import os
import unittest
from pathlib import Path
import sys
import uuid
import importlib.util
import asyncio
import base64
import hmac
import json

import httpx


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)



def load_app():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    os.environ.pop("OPA_URL", None)
    os.environ.setdefault("SAT_SECRET", "test-sat-secret")

    module_path = Path(__file__).resolve().parents[1] / "app" / "main.py"
    module_name = f"spawn_service_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    if spec.loader is None:
        raise RuntimeError("Failed to load spawn_service module")
    spec.loader.exec_module(module)
    return module.app


async def request(
    app: object, method: str, path: str, json: dict | None = None
) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        return await client.request(method, path, json=json)


class SpawnServiceTests(unittest.TestCase):
    def test_healthz_and_readyz(self):
        os.environ["SAT_REQUIRED"] = "false"
        app = load_app()
        healthz = asyncio.run(request(app, "GET", "/healthz"))
        self.assertEqual(healthz.status_code, 200)
        self.assertEqual(healthz.json()["status"], "ok")

        readyz = asyncio.run(request(app, "GET", "/readyz"))
        self.assertEqual(readyz.status_code, 200)
        self.assertEqual(readyz.json()["status"], "ready")

    def test_spawn_api_requires_request_id(self):
        os.environ["SAT_REQUIRED"] = "false"
        app = load_app()
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={"track": "netplus", "subject": "user-1", "tier": "free"},
            )
        )
        self.assertEqual(response.status_code, 400)

    def test_spawn_api_success(self):
        os.environ["SAT_REQUIRED"] = "false"
        app = load_app()
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-123",
                    "subject": "user-123",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["scenario_id"].startswith("scn-"))
        self.assertEqual(body["request_id"], "req-123")
        self.assertTrue(body["access_token"])
        self.assertTrue(body["sat"])

    def test_spawn_api_rejects_missing_sat(self):
        app = load_app()
        os.environ["SAT_REQUIRED"] = "true"
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-456",
                    "subject": "user-456",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(response.status_code, 401)
        os.environ["SAT_REQUIRED"] = "false"

    def test_spawn_api_mints_sat_claims(self):
        os.environ["SAT_REQUIRED"] = "false"
        os.environ["SAT_SECRET"] = "test-sat-secret"
        app = load_app()
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-789",
                    "subject": "user-789",
                    "tier": "pro",
                    "requested_limits": {"cpu": 1},
                },
            )
        )
        self.assertEqual(response.status_code, 200)
        token = response.json()["sat"]
        header_encoded, payload_encoded, signature = token.split(".")
        signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
        expected_signature = hmac.new(
            os.environ["SAT_SECRET"].encode("utf-8"), signing_input, "sha256"
        ).digest()
        expected_encoded = (
            base64.urlsafe_b64encode(expected_signature).rstrip(b"=").decode("utf-8")
        )
        self.assertEqual(signature, expected_encoded)
        payload = json.loads(b64url_decode(payload_encoded).decode("utf-8"))
        self.assertIn("jti", payload)
        self.assertIn("exp", payload)
        self.assertIn("iat", payload)
        self.assertEqual(payload["track"], "netplus")
        self.assertEqual(payload["template_id"], "netplus")
        self.assertEqual(payload["subject"], "user-789")
        self.assertEqual(payload["tier"], "pro")


if __name__ == "__main__":
    unittest.main()
