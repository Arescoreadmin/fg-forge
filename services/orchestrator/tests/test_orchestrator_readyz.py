import asyncio
import importlib.util
import os
from pathlib import Path
import sys
import unittest
import uuid

from fastapi import FastAPI, HTTPException
import httpx
from httpx import ASGITransport, AsyncClient


def load_orchestrator_module():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    module_path = repo_root / "services" / "orchestrator" / "app" / "main.py"
    module_name = f"orchestrator_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    if spec.loader is None:
        raise RuntimeError("Failed to load orchestrator module")
    spec.loader.exec_module(module)
    return module


class OrchestratorReadyzTests(unittest.TestCase):
    def test_readyz_fails_when_opa_unreachable(self):
        module = load_orchestrator_module()

        async def failing_opa():
            raise module.HTTPException(status_code=503, detail="opa unavailable")

        module._check_opa_ready = failing_opa

        async def run():
            transport = ASGITransport(app=module.app)
            async with AsyncClient(transport=transport, base_url="http://orch") as client:
                response = await client.get("/readyz")
            return response

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 503)

    def test_readyz_fails_when_scoreboard_unhealthy(self):
        module = load_orchestrator_module()

        async def ok_opa():
            return None

        module._check_opa_ready = ok_opa

        unhealthy_app = FastAPI()

        def _unhealthy_readyz():
            raise HTTPException(status_code=503, detail="down")

        unhealthy_app.add_api_route("/readyz", _unhealthy_readyz, methods=["GET"])

        def scoreboard_client():
            transport = ASGITransport(app=unhealthy_app)
            return AsyncClient(transport=transport, base_url="http://scoreboard")

        module._scoreboard_client = scoreboard_client

        async def run():
            transport = ASGITransport(app=module.app)
            async with AsyncClient(transport=transport, base_url="http://orch") as client:
                response = await client.get("/readyz")
            return response

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 503)

    def test_request_retries_bounded_on_timeout(self):
        os.environ["HTTP_MAX_RETRIES"] = "2"
        module = load_orchestrator_module()

        class DummyClient:
            def __init__(self):
                self.calls = 0

            async def request(self, *_args, **_kwargs):
                self.calls += 1
                raise httpx.ReadTimeout("timeout")

        client = DummyClient()

        async def no_sleep(_seconds: float) -> None:
            return None

        module._sleep = no_sleep

        async def run():
            with self.assertRaises(httpx.RequestError):
                await module._request_with_retries(client, "GET", "http://example.com")

        asyncio.run(run())
        self.assertEqual(client.calls, 3)
        os.environ.pop("HTTP_MAX_RETRIES", None)


if __name__ == "__main__":
    unittest.main()
