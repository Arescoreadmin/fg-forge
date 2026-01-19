import asyncio
import base64
from datetime import UTC, datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519



def _load_module(module_name: str):
    module = importlib.import_module(module_name)
    return importlib.reload(module)


def load_spawn_module():
    return _load_module("services.spawn_service.app.main")


def load_orchestrator_module():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    return _load_module("services.orchestrator.app.main")


def load_scoreboard_module():
    return _load_module("services.scoreboard.app.main")


class ScenarioCompletionIntegrationTests(unittest.TestCase):
    def test_completion_triggers_scoring_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["SAT_HMAC_SECRET"] = "test-sat-secret"
            os.environ["ORCHESTRATOR_INTERNAL_TOKEN"] = "orch-token"
            os.environ["SCOREBOARD_INTERNAL_TOKEN"] = "score-token"
            os.environ["STORAGE_ROOT"] = tmpdir

            spawn_module = load_spawn_module()
            orchestrator_module = load_orchestrator_module()
            scoreboard_module = load_scoreboard_module()

            scoreboard_app = scoreboard_module.create_app(
                scoreboard_module.ScoreboardConfig(
                    storage_root=Path(tmpdir),
                    nats_url="nats://memory",
                    event_bus_backend="memory",
                )
            )
            orchestrator_app = orchestrator_module.create_app(
                orchestrator_module.OrchestratorConfig(
                    template_dir=Path(os.environ["TEMPLATE_DIR"]),
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

            scenario_id = "scn-e2e"
            issued_at = int(datetime.now(UTC).timestamp())
            claims = spawn_module.SatClaims(
                jti=str(uuid.uuid4()),
                exp=issued_at + 300,
                iat=issued_at,
                track="netplus",
                template_id="netplus",
                subject="user-1",
                tenant_id="tenant-1",
                tier="free",
                scenario_id=scenario_id,
            )
            sat = spawn_module.generate_sat(claims)
            orchestrator_module.verify_sat(sat)

            orchestrator_module.scenarios.clear()
            orchestrator_module.scenarios[scenario_id] = orchestrator_module.ScenarioState(
                scenario_id=scenario_id,
                request_id="req-1",
                track="netplus",
                subject="user-1",
                tenant_id="tenant-1",
                tier="FREE",
                retention_days=30,
                status=orchestrator_module.ScenarioStatus.RUNNING,
            )

            asyncio.run(
                orchestrator_module.complete_scenario(scenario_id, completion_reason="finished")
            )

            results_dir = Path(tmpdir) / "scenarios" / scenario_id / "results"
            score_path = results_dir / "score.json"
            verdict_path = results_dir / "verdict.sig"
            public_key_path = results_dir / "verdict.pub"
            self.assertTrue(score_path.exists())
            self.assertTrue(verdict_path.exists())
            self.assertTrue(public_key_path.exists())
            evidence_files = list(results_dir.glob("evidence.tar.*"))
            self.assertEqual(len(evidence_files), 1)

            score_bytes = score_path.read_bytes()
            evidence_bytes = evidence_files[0].read_bytes()
            score_hash = hashlib.sha256(score_bytes).hexdigest()
            evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()

            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
            signature = base64.b64decode(verdict["signature"])
            public_key_bytes = base64.b64decode(public_key_path.read_text(encoding="utf-8"))
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, f"{score_hash}:{evidence_hash}".encode())


if __name__ == "__main__":
    unittest.main()
