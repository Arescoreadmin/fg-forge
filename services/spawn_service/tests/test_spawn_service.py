import os
import unittest
from pathlib import Path
import sys
import uuid
import importlib.util
import asyncio

import httpx



def load_app():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    os.environ.pop("OPA_URL", None)

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
            request(app, "POST", "/api/spawn", json={"track": "netplus"})
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
                json={"track": "netplus", "request_id": "req-123"},
            )
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["scenario_id"].startswith("scn-"))
        self.assertEqual(body["request_id"], "req-123")
        self.assertTrue(body["access_token"])

    def test_spawn_api_rejects_missing_sat(self):
        app = load_app()
        os.environ["SAT_REQUIRED"] = "true"
        response = asyncio.run(
            request(
                app,
                "POST",
                "/api/spawn",
                json={"track": "netplus", "request_id": "req-456"},
            )
        )
        self.assertEqual(response.status_code, 401)
        os.environ["SAT_REQUIRED"] = "false"


if __name__ == "__main__":
    unittest.main()
