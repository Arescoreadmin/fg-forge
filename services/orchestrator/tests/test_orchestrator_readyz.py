import asyncio
import importlib.util
import os
import sys
import unittest
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
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


if __name__ == "__main__":
    unittest.main()
