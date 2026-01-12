import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from httpx import ASGITransport, AsyncClient


def _load_module(module_path: Path, prefix: str):
    module_name = f"{prefix}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    if spec.loader is None:
        raise RuntimeError(f"Failed to load module {module_path}")
    spec.loader.exec_module(module)
    return module


def load_spawn_module():
    repo_root = Path(__file__).resolve().parents[3]
    spawn_root = repo_root / "services" / "spawn_service"
    if str(spawn_root) not in sys.path:
        sys.path.insert(0, str(spawn_root))
    module_path = repo_root / "services" / "spawn_service" / "app" / "main.py"
    return _load_module(module_path, "spawn_main")


def load_orchestrator_module():
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["TEMPLATE_DIR"] = str(repo_root / "templates")
    module_path = repo_root / "services" / "orchestrator" / "app" / "main.py"
    return _load_module(module_path, "orchestrator_main")


def load_scoreboard_module():
    repo_root = Path(__file__).resolve().parents[3]
    module_path = repo_root / "services" / "scoreboard" / "app" / "main.py"
    return _load_module(module_path, "scoreboard_main")


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

            scenario_id = "scn-e2e"
            issued_at = int(datetime.now(timezone.utc).timestamp())
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
            orchestrator_module.scenarios[scenario_id] = (
                orchestrator_module.ScenarioState(
                    scenario_id=scenario_id,
                    request_id="req-1",
                    track="netplus",
                    subject="user-1",
                    tenant_id="tenant-1",
                    tier="FREE",
                    retention_days=30,
                    status=orchestrator_module.ScenarioStatus.RUNNING,
                )
            )

            def scoreboard_client():
                transport = ASGITransport(app=scoreboard_module.app)
                return AsyncClient(transport=transport, base_url="http://scoreboard")

            orchestrator_module._scoreboard_client = scoreboard_client

            asyncio.run(
                orchestrator_module.complete_scenario(
                    scenario_id, completion_reason="finished"
                )
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
            public_key_bytes = base64.b64decode(
                public_key_path.read_text(encoding="utf-8")
            )
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, f"{score_hash}:{evidence_hash}".encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
