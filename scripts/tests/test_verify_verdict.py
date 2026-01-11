import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from scripts.verify_verdict import verify_verdict


class VerifyVerdictTests(unittest.TestCase):
    def test_verify_verdict_success(self):
        key = ed25519.Ed25519PrivateKey.generate()
        score_payload = {"score": 0.9, "computed_at": datetime.now(timezone.utc).isoformat()}
        score_bytes = json.dumps(score_payload, sort_keys=True).encode("utf-8")
        evidence_bytes = b"evidence"
        score_hash = __import__("hashlib").sha256(score_bytes).hexdigest()
        evidence_hash = __import__("hashlib").sha256(evidence_bytes).hexdigest()
        signature = key.sign(f"{score_hash}:{evidence_hash}".encode("utf-8"))
        verdict = {
            "scenario_id": "scn-1",
            "score_hash": score_hash,
            "evidence_hash": evidence_hash,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "signature": base64.b64encode(signature).decode("utf-8"),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            score_path = tmp_path / "score.json"
            evidence_path = tmp_path / "evidence.tar.gz"
            verdict_path = tmp_path / "verdict.sig"
            pub_path = tmp_path / "verdict.pub"

            score_path.write_bytes(score_bytes)
            evidence_path.write_bytes(evidence_bytes)
            verdict_path.write_text(json.dumps(verdict), encoding="utf-8")
            public_bytes = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            pub_path.write_text(
                base64.b64encode(public_bytes).decode("utf-8"), encoding="utf-8"
            )

            result = verify_verdict(score_path, evidence_path, verdict_path, pub_path)
            self.assertTrue(result.ok)
            self.assertEqual(result.errors, ())

    def test_verify_verdict_hash_mismatch(self):
        key = ed25519.Ed25519PrivateKey.generate()
        score_bytes = b"score"
        evidence_bytes = b"evidence"
        score_hash = __import__("hashlib").sha256(score_bytes).hexdigest()
        evidence_hash = __import__("hashlib").sha256(evidence_bytes).hexdigest()
        signature = key.sign(f"{score_hash}:{evidence_hash}".encode("utf-8"))
        verdict = {
            "scenario_id": "scn-1",
            "score_hash": score_hash,
            "evidence_hash": evidence_hash,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "signature": base64.b64encode(signature).decode("utf-8"),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            score_path = tmp_path / "score.json"
            evidence_path = tmp_path / "evidence.tar.gz"
            verdict_path = tmp_path / "verdict.sig"
            pub_path = tmp_path / "verdict.pub"

            score_path.write_bytes(score_bytes)
            evidence_path.write_bytes(b"tampered")
            verdict_path.write_text(json.dumps(verdict), encoding="utf-8")
            public_bytes = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            pub_path.write_text(
                base64.b64encode(public_bytes).decode("utf-8"), encoding="utf-8"
            )

            result = verify_verdict(score_path, evidence_path, verdict_path, pub_path)
            self.assertFalse(result.ok)
            self.assertIn("evidence hash mismatch", result.errors)


if __name__ == "__main__":
    unittest.main()
