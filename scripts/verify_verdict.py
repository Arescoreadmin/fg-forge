#!/usr/bin/env python3
"""Offline verdict verification CLI.

Verifies score.json and evidence bundle hashes against a signed verdict.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    errors: tuple[str, ...]


def _hash_file(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def _load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def _load_verdict(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_verdict(
    score_path: Path,
    evidence_path: Path,
    verdict_sig_path: Path,
    verdict_pub_path: Path,
) -> VerificationResult:
    errors: list[str] = []

    for required_path, label in (
        (score_path, "score.json"),
        (evidence_path, "evidence bundle"),
        (verdict_sig_path, "verdict.sig"),
        (verdict_pub_path, "verdict.pub"),
    ):
        if not required_path.exists():
            errors.append(f"missing {label}: {required_path}")

    if errors:
        return VerificationResult(False, tuple(errors))

    verdict = _load_verdict(verdict_sig_path)
    score_hash = _hash_file(score_path)
    evidence_hash = _hash_file(evidence_path)

    expected_score_hash = verdict.get("score_hash")
    expected_evidence_hash = verdict.get("evidence_hash")
    signature_b64 = verdict.get("signature")

    if not expected_score_hash:
        errors.append("verdict missing score_hash")
    elif expected_score_hash != score_hash:
        errors.append("score hash mismatch")

    if not expected_evidence_hash:
        errors.append("verdict missing evidence_hash")
    elif expected_evidence_hash != evidence_hash:
        errors.append("evidence hash mismatch")

    if not signature_b64:
        errors.append("verdict missing signature")

    if not errors:
        try:
            signature = base64.b64decode(signature_b64)
            public_key = _load_public_key(verdict_pub_path)
            public_key.verify(signature, f"{score_hash}:{evidence_hash}".encode())
        except Exception as exc:  # pragma: no cover - explicit error path
            errors.append(f"signature verification failed: {exc}")

    return VerificationResult(ok=not errors, errors=tuple(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify verdict signature offline.")
    parser.add_argument("score_json", type=Path, help="Path to score.json")
    parser.add_argument("evidence_bundle", type=Path, help="Path to evidence bundle")
    parser.add_argument("verdict_sig", type=Path, help="Path to verdict.sig")
    parser.add_argument("verdict_pub", type=Path, help="Path to verdict.pub")
    args = parser.parse_args()

    result = verify_verdict(
        args.score_json, args.evidence_bundle, args.verdict_sig, args.verdict_pub
    )
    if result.ok:
        print("PASS: verdict verification succeeded")
        return 0

    print("FAIL: verdict verification failed")
    for error in result.errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
