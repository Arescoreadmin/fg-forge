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
import tempfile
import time
from unittest import mock

import httpx


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


DEFAULT_ENTITLEMENTS = {
    "user-1": {"tier": "free", "retention_days": 30},
    "user-123": {"tier": "free", "retention_days": 30},
    "user-456": {"tier": "free", "retention_days": 30},
    "user-789": {"tier": "pro", "retention_days": 90},
    "user-rate": {"tier": "free", "retention_days": 30},
    "user-quo": {"tier": "free", "retention_days": 30},
    "user-redis": {"tier": "free", "retention_days": 30},
    "user-dev": {"tier": "free", "retention_days": 30},
    "user-unknown": {"tier": "unknown", "retention_days": 30},
    "user-track": {"tier": "free", "retention_days": 30},
}


def write_entitlements(entries: dict) -> str:
    handle = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
    json.dump(entries, handle)
    handle.close()
    return handle.name


def load_module():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    os.environ.pop("OPA_URL", None)
    if "SAT_HMAC_SECRET" not in os.environ and "SAT_SECRET" not in os.environ:
        os.environ["SAT_HMAC_SECRET"] = "test-sat-secret"

    service_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(service_root))
    module_path = service_root / "app" / "main.py"
    module_name = f"spawn_service_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    if spec.loader is None:
        raise RuntimeError("Failed to load spawn_service module")
    spec.loader.exec_module(module)
    return module


def load_app():
    return load_module().app


async def request(
    app: object,
    method: str,
    path: str,
    json: dict | None = None,
    headers: dict | None = None,
) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        return await client.request(method, path, json=json, headers=headers)


class SpawnServiceTests(unittest.TestCase):
    def setUp(self):
        os.environ["ENTITLEMENTS_FILE"] = write_entitlements(DEFAULT_ENTITLEMENTS)
        os.environ.pop("ENTITLEMENTS_REDIS_URL", None)

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
        os.environ["SAT_HMAC_SECRET"] = "test-sat-secret"
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
            os.environ["SAT_HMAC_SECRET"].encode("utf-8"), signing_input, "sha256"
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
        self.assertEqual(payload["tenant_id"], "user-789")
        self.assertEqual(payload["tier"], "PRO")
        self.assertEqual(payload["retention_days"], 90)

    def test_spawn_api_missing_subject_identifier(self):
        os.environ["SAT_REQUIRED"] = "false"
        app = load_app()
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-missing-subject",
                    "subject": "",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(response.status_code, 403)

    def test_spawn_rate_limit_exceeded(self):
        os.environ["SAT_REQUIRED"] = "false"
        module = load_module()
        module.PLAN_ENTITLEMENTS["FREE"] = module.PlanEntitlements(
            max_spawns_per_minute=1,
            max_concurrent_scenarios=module.PLAN_ENTITLEMENTS["FREE"].max_concurrent_scenarios,
            allowed_tracks=module.PLAN_ENTITLEMENTS["FREE"].allowed_tracks,
        )
        app = module.app
        first = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-rate-1",
                    "subject": "user-rate",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(first.status_code, 200)
        second = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-rate-2",
                    "subject": "user-rate",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(second.status_code, 429)

    def test_spawn_concurrent_quota_exceeded(self):
        os.environ["SAT_REQUIRED"] = "false"
        module = load_module()
        module.PLAN_ENTITLEMENTS["FREE"] = module.PlanEntitlements(
            max_spawns_per_minute=module.PLAN_ENTITLEMENTS["FREE"].max_spawns_per_minute,
            max_concurrent_scenarios=1,
            allowed_tracks=module.PLAN_ENTITLEMENTS["FREE"].allowed_tracks,
        )
        app = module.app
        first = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-quo-1",
                    "subject": "user-quo",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(first.status_code, 200)
        second = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-quo-2",
                    "subject": "user-quo",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(second.status_code, 409)

    def test_spawn_rate_limit_redis_unavailable_fails_closed(self):
        os.environ["SAT_REQUIRED"] = "false"
        os.environ["REDIS_URL"] = "redis://localhost:6390"
        module = load_module()
        app = module.app

        class FakeRedis:
            def incr(self, _key):
                raise Exception("down")

            def expire(self, _key, _ttl):
                return None

        module.spawn_limiter._redis_client = FakeRedis()
        module.spawn_limiter._redis_required = True

        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-redis-down",
                    "subject": "user-redis",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(response.status_code, 503)
        os.environ.pop("REDIS_URL", None)

    def test_spawn_rate_limit_fallback_warning_when_no_redis(self):
        os.environ["SAT_REQUIRED"] = "false"
        os.environ.pop("REDIS_URL", None)
        module = load_module()
        app = module.app

        with self.assertLogs("forge_spawn_service", level="WARNING") as logs:
            response = asyncio.run(
                request(
                    app,
                    "POST",
                    "/api/spawn",
                    json={
                        "track": "netplus",
                        "request_id": "req-dev-fallback",
                        "subject": "user-dev",
                        "tier": "free",
                    },
                )
            )
        self.assertEqual(response.status_code, 200)
        warnings = [
            record
            for record in logs.output
            if "REDIS_URL not set; using in-memory rate limits" in record
        ]
        self.assertTrue(warnings)

    def test_request_retries_bounded_on_timeout(self):
        os.environ["HTTP_MAX_RETRIES"] = "2"
        module = load_module()
        call_count = {"count": 0}

        def fake_request(*_args, **_kwargs):
            call_count["count"] += 1
            raise module.requests.Timeout("timeout")

        with mock.patch.object(module.requests, "request", side_effect=fake_request):
            with mock.patch.object(module, "_sleep", return_value=None):
                with self.assertRaises(module.requests.RequestException):
                    module._request_with_retries(
                        "GET",
                        "http://example.com/health",
                    )
        self.assertEqual(call_count["count"], 3)
        os.environ.pop("HTTP_MAX_RETRIES", None)

    def test_sat_secret_alias_warning_emitted_once(self):
        os.environ.pop("SAT_HMAC_SECRET", None)
        os.environ["SAT_SECRET"] = "legacy-secret"
        module = load_module()
        with self.assertLogs("forge_spawn_service", level="WARNING") as logs:
            module._get_sat_secret()
            module._get_sat_secret()
        warnings = [record for record in logs.output if "SAT_SECRET is deprecated" in record]
        self.assertEqual(len(warnings), 1)

    def test_spawn_api_rejects_subject_mismatch(self):
        os.environ["SAT_REQUIRED"] = "false"
        os.environ["SAT_HMAC_SECRET"] = "test-sat-secret"
        module = load_module()
        app = module.app
        issued_at = module._sat_issued_at()
        sat = module.generate_sat(
            module.SatClaims(
                jti=str(uuid.uuid4()),
                exp=module._sat_expiration(issued_at),
                iat=issued_at,
                track="netplus",
                template_id="netplus",
                subject="user-1",
                tenant_id="user-1",
                tier="free",
            )
        )
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-mismatch",
                    "subject": "user-2",
                    "tier": "free",
                },
                headers={"x-sat": sat},
            )
        )
        self.assertEqual(response.status_code, 403)

    def test_spawn_api_rejects_unknown_tier(self):
        os.environ["SAT_REQUIRED"] = "false"
        app = load_app()
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-unknown-tier",
                    "subject": "user-unknown",
                    "tier": "unknown",
                },
            )
        )
        self.assertEqual(response.status_code, 403)

    def test_spawn_api_rejects_track_not_allowed_for_tier(self):
        os.environ["SAT_REQUIRED"] = "false"
        app = load_app()
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "cissp",
                    "request_id": "req-track-tier",
                    "subject": "user-track",
                    "tier": "free",
                },
            )
        )
        self.assertEqual(response.status_code, 403)

    def test_spawn_receipt_overrides_store(self):
        os.environ["SAT_REQUIRED"] = "false"
        os.environ["RECEIPT_HMAC_SECRET"] = "receipt-secret"
        entries = dict(DEFAULT_ENTITLEMENTS)
        entries["user-receipt"] = {"tier": "free", "retention_days": 30}
        os.environ["ENTITLEMENTS_FILE"] = write_entitlements(entries)
        app = load_app()
        exp = int(time.time()) + 3600
        receipt_payload = {
            "tenant_id": "user-receipt",
            "tier": "pro",
            "retention_days": 45,
            "exp": exp,
            "subject": "user-receipt",
        }
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(receipt_payload).encode("utf-8")
        ).rstrip(b"=").decode("utf-8")
        signature = hmac.new(
            os.environ["RECEIPT_HMAC_SECRET"].encode("utf-8"),
            payload_encoded.encode("utf-8"),
            "sha256",
        ).digest()
        signature_encoded = (
            base64.urlsafe_b64encode(signature).rstrip(b"=").decode("utf-8")
        )
        receipt = f"{payload_encoded}.{signature_encoded}"
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "ccna",
                    "request_id": "req-receipt",
                    "subject": "user-receipt",
                },
                headers={"x-receipt-token": receipt},
            )
        )
        self.assertEqual(response.status_code, 200)
        token = response.json()["sat"]
        _, payload_encoded, _ = token.split(".")
        payload = json.loads(b64url_decode(payload_encoded).decode("utf-8"))
        self.assertEqual(payload["tier"], "PRO")
        self.assertEqual(payload["retention_days"], 45)

    def test_spawn_receipt_invalid_fails_closed(self):
        os.environ["SAT_REQUIRED"] = "false"
        os.environ["RECEIPT_HMAC_SECRET"] = "receipt-secret"
        entries = dict(DEFAULT_ENTITLEMENTS)
        entries["user-bad-receipt"] = {"tier": "free", "retention_days": 30}
        os.environ["ENTITLEMENTS_FILE"] = write_entitlements(entries)
        app = load_app()
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={
                    "track": "netplus",
                    "request_id": "req-bad-receipt",
                    "subject": "user-bad-receipt",
                },
                headers={"x-receipt-token": "invalid.token"},
            )
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
