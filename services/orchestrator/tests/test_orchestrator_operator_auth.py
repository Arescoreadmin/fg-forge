import asyncio
import importlib.util
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

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


class OrchestratorOperatorAuthTests(unittest.TestCase):
    def test_completion_requires_operator_token(self):
        module = load_orchestrator_module()
        os.environ["ORCHESTRATOR_INTERNAL_TOKEN"] = "internal"
        os.environ["OPERATOR_TOKEN"] = "operator"
        scenario_id = "scn-auth"
        module.scenarios[scenario_id] = module.ScenarioState(
            scenario_id=scenario_id,
            request_id="req-1",
            track="netplus",
            status=module.ScenarioStatus.RUNNING,
        )

        async def run():
            transport = ASGITransport(app=module.app)
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
