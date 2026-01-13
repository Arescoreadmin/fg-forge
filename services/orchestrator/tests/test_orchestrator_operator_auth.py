import asyncio
import importlib
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from httpx import ASGITransport, AsyncClient


def load_orchestrator_module():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    module = importlib.import_module("services.orchestrator.app.main")
    return importlib.reload(module)


class OrchestratorOperatorAuthTests(unittest.TestCase):
    def test_completion_requires_operator_token(self):
        module = load_orchestrator_module()
        os.environ["ORCHESTRATOR_INTERNAL_TOKEN"] = "internal"
        os.environ["OPERATOR_TOKEN"] = "operator"
        scenario_id = "scn-auth"
        app = module.create_app(
            module.OrchestratorConfig(
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
        )
        app.state.scenarios[scenario_id] = module.ScenarioState(
            scenario_id=scenario_id,
            request_id="req-1",
            track="netplus",
            status=module.ScenarioStatus.RUNNING,
        )

        async def run():
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://orch") as client:
                response = await client.post(
                    f"/internal/scenario/{scenario_id}/complete",
                    headers={"x-internal-token": "internal"},
                    json={
                        "completion_reason": "done",
                        "completion_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )
            return response

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
