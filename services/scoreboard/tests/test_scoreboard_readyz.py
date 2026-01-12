import asyncio
import importlib.util
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from httpx import ASGITransport, AsyncClient


def load_scoreboard_module(storage_root: Path, signing_key_path: str | None):
    repo_root = Path(__file__).resolve().parents[3]
    os.environ["STORAGE_ROOT"] = str(storage_root)
    if signing_key_path is None:
        os.environ.pop("SIGNING_KEY_PATH", None)
    else:
        os.environ["SIGNING_KEY_PATH"] = signing_key_path
    module_path = repo_root / "services" / "scoreboard" / "app" / "main.py"
    module_name = f"scoreboard_main_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    if spec.loader is None:
        raise RuntimeError("Failed to load scoreboard module")
    spec.loader.exec_module(module)
    return module


def run_readyz(module):
    async def run():
        transport = ASGITransport(app=module.app)
        async with AsyncClient(transport=transport, base_url="http://scoreboard") as client:
            response = await client.get("/readyz")
        return response

    return asyncio.run(run())


class ScoreboardReadyzTests(unittest.TestCase):
    def test_readyz_fails_when_storage_not_writable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir)
            scenarios_dir = storage_root / "scenarios"
            scenarios_dir.write_text("not-a-directory", encoding="utf-8")
            key_path = storage_root / "signing.pem"
            key = ed25519.Ed25519PrivateKey.generate()
            key_path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            module = load_scoreboard_module(storage_root, str(key_path))
            response = run_readyz(module)
            self.assertEqual(response.status_code, 503)

    def test_readyz_fails_when_signing_key_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir)
            module = load_scoreboard_module(storage_root, str(storage_root / "missing.pem"))
            response = run_readyz(module)
            self.assertEqual(response.status_code, 503)

    def test_readyz_fails_on_egress_config_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir)
            key_path = storage_root / "signing.pem"
            key = ed25519.Ed25519PrivateKey.generate()
            key_path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            os.environ["EGRESS_GATEWAY_URL"] = "http://egress"
            os.environ["EGRESS_DRY_RUN_EXPECTED"] = "false"
            module = load_scoreboard_module(storage_root, str(key_path))

            class FakeResponse:
                status_code = 200

                def json(self):
                    return {"dry_run": True}

            with mock.patch.object(
                module, "_request_with_retries", return_value=FakeResponse()
            ):
                response = run_readyz(module)
            self.assertEqual(response.status_code, 503)
            os.environ.pop("EGRESS_GATEWAY_URL", None)
            os.environ.pop("EGRESS_DRY_RUN_EXPECTED", None)


if __name__ == "__main__":
    unittest.main()
