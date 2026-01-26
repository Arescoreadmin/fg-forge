import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest

import httpx

from services.orchestrator.app.main import OrchestratorConfig, create_app as create_orchestrator_app
from services.scoreboard.app.main import ScoreboardConfig, create_app as create_scoreboard_app
from services.spawn_service.app.main import SpawnConfig, create_app as create_spawn_app


class ContractGoldenPathTests(unittest.TestCase):
    def test_spawn_to_scoreboard_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(__file__).resolve().parents[3]
            entitlements_path = Path(tmpdir) / "entitlements.json"
            entitlements_path.write_text(
                json.dumps({"user-e2e": {"tier": "free", "retention_days": 30}}),
                encoding="utf-8",
            )

            os.environ["FORGE_ENV"] = "dev"
            os.environ["SAT_HMAC_SECRET"] = "test-sat-secret"
            os.environ["ET_HMAC_SECRET"] = "test-et-secret"
            os.environ["RECEIPT_HMAC_SECRET"] = "test-receipt-secret"
            os.environ["ORCHESTRATOR_INTERNAL_TOKEN"] = "orch-token"
            os.environ["OPERATOR_TOKEN"] = "operator-token"
            os.environ["SCOREBOARD_INTERNAL_TOKEN"] = "score-token"
            os.environ["ENTITLEMENTS_FILE"] = entitlements_path.as_posix()
            os.environ["SAT_REQUIRED"] = "false"
            os.environ.pop("OPA_URL", None)

            scoreboard_app = create_scoreboard_app(
                ScoreboardConfig(
                    storage_root=Path(tmpdir),
                    nats_url="nats://memory",
                    event_bus_backend="memory",
                )
            )

            orchestrator_app = create_orchestrator_app(
                OrchestratorConfig(
                    template_dir=repo_root / "templates",
                    opa_url="http://unused",
                    nats_url="nats://memory",
                    scoreboard_url="http://scoreboard",
                    scoreboard_app=scoreboard_app,
                    storage_root=Path(tmpdir),
                    policy_backend="allow_all",
                    container_backend="stub",
                    event_bus_backend="memory",
                    storage_backend="fs",
                )
            )

            spawn_app = create_spawn_app(
                SpawnConfig(
                    template_dir=repo_root / "templates",
                    opa_url=None,
                    orchestrator_url="http://orchestrator",
                    orchestrator_app=orchestrator_app,
                    request_id_header="x-request-id",
                    tenant_id_header="x-tenant-id",
                    client_id_header="x-client-id",
                    entitlement_receipt_header="x-receipt-token",
                )
            )

            request_id = "req-e2e-001"
            scenario_id = "scn-contract-golden"
            subject = "user-e2e"

            async def run_flow() -> (
                tuple[httpx.Response, httpx.Response, httpx.Response, httpx.Response]
            ):
                spawn_transport = httpx.ASGITransport(app=spawn_app)
                orchestrator_transport = httpx.ASGITransport(app=orchestrator_app)
                scoreboard_transport = httpx.ASGITransport(app=scoreboard_app)

                async with httpx.AsyncClient(
                    transport=spawn_transport, base_url="http://spawn"
                ) as spawn_client:
                    spawn_response = await spawn_client.post(
                        "/api/spawn",
                        json={
                            "track": "netplus",
                            "request_id": request_id,
                            "subject": subject,
                            "tier": "free",
                            "scenario_id": scenario_id,
                        },
                        headers={
                            "x-request-id": request_id,
                            "x-tenant-id": subject,
                        },
                    )

                async with httpx.AsyncClient(
                    transport=orchestrator_transport,
                    base_url="http://orchestrator",
                ) as orchestrator_client:
                    completion_response = await orchestrator_client.post(
                        f"/internal/scenario/{scenario_id}/complete",
                        json={
                            "completion_reason": "finished",
                        },
                        headers={
                            "x-request-id": request_id,
                            "x-internal-token": "orch-token",
                            "x-operator-token": "operator-token",
                        },
                    )

                async with httpx.AsyncClient(
                    transport=scoreboard_transport,
                    base_url="http://scoreboard",
                ) as scoreboard_client:
                    score_response = await scoreboard_client.get(f"/v1/scores/{scenario_id}")
                    audit_response = await scoreboard_client.get(f"/v1/audit/{scenario_id}/verify")

                return spawn_response, completion_response, score_response, audit_response

            spawn_response, completion_response, score_response, audit_response = asyncio.run(
                run_flow()
            )

            self.assertEqual(spawn_response.status_code, 200)
            self.assertEqual(completion_response.status_code, 200)
            self.assertEqual(score_response.status_code, 200)
            self.assertEqual(audit_response.status_code, 200)

            score_body = score_response.json()
            audit_body = audit_response.json()

            self.assertEqual(score_body["scenario_id"], scenario_id)
            self.assertTrue(score_body["evidence_sha256"])
            self.assertTrue(audit_body["audit_ok"])


if __name__ == "__main__":
    unittest.main()
