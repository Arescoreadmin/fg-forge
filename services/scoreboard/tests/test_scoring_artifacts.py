import base64
import gzip
import importlib.util
import json
import sys
import tarfile
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path


def load_module():
    repo_root = Path(__file__).resolve().parents[3]
    module_path = repo_root / "services" / "scoreboard" / "app" / "main.py"
    module_name = f"scoreboard_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    if spec.loader is None:
        raise RuntimeError("Failed to load scoreboard module")
    spec.loader.exec_module(module)
    return module


class ScoreboardArtifactsTests(unittest.TestCase):
    def test_score_json_deterministic(self):
        module = load_module()
        fixed_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
        score = module.ScoreResult(
            scenario_id="scn-1",
            track="netplus",
            score=0.5,
            passed=1,
            total=2,
            criteria=[],
            computed_at=fixed_time,
        )
        first = module._score_json_bytes(score)
        second = module._score_json_bytes(score)
        self.assertEqual(first, second)
        payload = json.loads(first.decode("utf-8"))
        self.assertEqual(payload["computed_at"], fixed_time.isoformat())

    def test_build_evidence_bundle_includes_artifacts(self):
        module = load_module()
        scenario_id = "scn-123"
        with tempfile.TemporaryDirectory() as tmpdir:
            artifacts_dir = Path(tmpdir) / scenario_id / "artifacts"
            artifacts_dir.mkdir(parents=True)
            (artifacts_dir / "sample.txt").write_text("artifact-data", encoding="utf-8")
            module.STORAGE_ROOT = Path(tmpdir)
            module.append_audit_event(
                scenario_id=scenario_id,
                event_type="scenario.create",
                actor="user-1",
                correlation_id="req-1",
                details={"track": "netplus"},
            )
            bundle = module.build_evidence_bundle(
                scenario_id,
                "netplus",
                "s3://forge-evidence/scn-123/evidence.tar.gz",
                tmpdir,
                module.audit_log_path(scenario_id),
                "user-1",
                "tenant-1",
            )

            if bundle.filename.endswith(".zst"):
                try:
                    import zstandard as zstd
                except ImportError as exc:  # pragma: no cover
                    self.fail(f"zstandard unavailable for {bundle.filename}: {exc}")
                raw_tar = zstd.ZstdDecompressor().decompress(bundle.payload)
            else:
                raw_tar = gzip.decompress(bundle.payload)

            with tarfile.open(fileobj=BytesIO(raw_tar), mode="r:") as tar:
                names = tar.getnames()
                manifest = json.loads(tar.extractfile("manifest.json").read())
            self.assertIn("logs/scoreboard.log", names)
            self.assertIn("telemetry/scoreboard.json", names)
            self.assertIn("source_evidence.txt", names)
            self.assertIn("artifacts/sample.txt", names)
            self.assertIn("audit/audit.jsonl", names)
            self.assertEqual(manifest["subject"], "user-1")
            self.assertEqual(manifest["tenant_id"], "tenant-1")
            self.assertIn("audit_sha256", manifest)

    def test_audit_chain_detects_tampering(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmpdir:
            module.STORAGE_ROOT = Path(tmpdir)
            scenario_id = "scn-audit"
            module.append_audit_event(
                scenario_id=scenario_id,
                event_type="scenario.create",
                actor="user-1",
                correlation_id="req-1",
                details={"track": "netplus"},
            )
            module.append_audit_event(
                scenario_id=scenario_id,
                event_type="score.finalized",
                actor="user-1",
                correlation_id="req-2",
                details={"score": 1.0},
            )
            audit_path = module.audit_log_path(scenario_id)
            self.assertTrue(module.verify_audit_chain(audit_path))
            lines = audit_path.read_text(encoding="utf-8").splitlines()
            tampered = json.loads(lines[0])
            tampered["details"]["track"] = "cissp"
            lines[0] = json.dumps(tampered, separators=(",", ":"))
            audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(module.verify_audit_chain(audit_path))

    def test_sign_verdict_uses_hashes(self):
        module = load_module()
        module.SIGNING_KEY = module.ed25519.Ed25519PrivateKey.generate()
        score_hash = "a" * 64
        evidence_hash = "b" * 64
        verdict = module.sign_verdict(score_hash, evidence_hash, "scn-1")
        message = f"{score_hash}:{evidence_hash}".encode("utf-8")
        signature_bytes = base64.b64decode(verdict.signature)
        module.SIGNING_KEY.public_key().verify(signature_bytes, message)

    def test_store_score_artifacts_filesystem(self):
        module = load_module()
        module.SIGNING_KEY = module.ed25519.Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as tmpdir:
            module.STORAGE_ROOT = Path(tmpdir)
            scenario_id = "scn-local"
            score = module.ScoreResult(
                scenario_id=scenario_id,
                track="netplus",
                score=1.0,
                passed=1,
                total=1,
                criteria=[],
            )
            score_bytes = module._score_json_bytes(score)
            score_hash = module._hash_bytes(score_bytes)
            evidence = module.build_evidence_bundle(
                scenario_id, "netplus", "", artifacts_root=None
            )
            evidence_hash = module._hash_bytes(evidence.payload)
            verdict = module.sign_verdict(score_hash, evidence_hash, scenario_id)
            score_path, evidence_path, verdict_path, pub_path = (
                module.store_score_artifacts_filesystem(
                    scenario_id, score_bytes, evidence, verdict
                )
            )

            results_dir = Path(tmpdir) / "scenarios" / scenario_id / "results"
            self.assertEqual(Path(score_path), results_dir / "score.json")
            self.assertTrue(Path(evidence_path).exists())
            self.assertTrue(Path(verdict_path).exists())
            self.assertTrue(Path(pub_path).exists())


if __name__ == "__main__":
    unittest.main()
