import asyncio
import importlib
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
    module = importlib.import_module("services.orchestrator.app.main")
    return importlib.reload(module)


class OrchestratorReadyzTests(unittest.TestCase):
    def test_readyz_fails_when_opa_unreachable(self):
        module = load_orchestrator_module()
        config = module.OrchestratorConfig(
            template_dir=Path(os.environ["TEMPLATE_DIR"]),
            opa_url="http://unused",
            nats_url="nats://memory",
            scoreboard_url="http://scoreboard",
            scoreboard_app=None,
            storage_root=Path("storage"),
            policy_backend="allow_all",
            container_backend="stub",
            event_bus_backend="memory",
            storage_backend="fs",
        )
        app = module.create_app(config)

        class FailingPolicy(module.PolicyEvaluator):
            async def allow(self, input_payload: dict):
                return False, "policy unavailable"

            async def ready(self):
                raise module.HTTPException(status_code=503, detail="opa unavailable")

        app.state.policy_evaluator = FailingPolicy()

        async def run():
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://orch") as client:
                response = await client.get("/readyz")
            return response

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 503)

    def test_readyz_fails_when_scoreboard_unhealthy(self):
        module = load_orchestrator_module()
        config = module.OrchestratorConfig(
            template_dir=Path(os.environ["TEMPLATE_DIR"]),
            opa_url="http://unused",
            nats_url="nats://memory",
            scoreboard_url="http://scoreboard",
            scoreboard_app=None,
            storage_root=Path("storage"),
            policy_backend="allow_all",
            container_backend="stub",
            event_bus_backend="memory",
            storage_backend="fs",
        )
        app = module.create_app(config)

        unhealthy_app = FastAPI()

        def _unhealthy_readyz():
            raise HTTPException(status_code=503, detail="down")

        unhealthy_app.add_api_route("/readyz", _unhealthy_readyz, methods=["GET"])

        class UnhealthyScoreboardClient(module.ScoreboardClient):
            async def get_ready(self) -> httpx.Response:
                transport = ASGITransport(app=unhealthy_app)
                async with AsyncClient(
                    transport=transport, base_url="http://scoreboard"
                ) as client:
                    return await client.get("/readyz")

            async def post_score(self, scenario_id: str, payload: dict, headers: dict):
                raise RuntimeError("not used")

        app.state.scoreboard_client = UnhealthyScoreboardClient()

        async def run():
            transport = ASGITransport(app=app)
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
