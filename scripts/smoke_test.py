#!/usr/bin/env python3
"""One-command smoke test for staging compose."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Iterable
from urllib import request, error


COMPOSE_FILES = ["compose.yml", "compose.staging.yml"]


def _compose_cmd(args: Iterable[str]) -> list[str]:
    return ["docker", "compose", "-f", COMPOSE_FILES[0], "-f", COMPOSE_FILES[1], *args]


def _default_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("SAT_HMAC_SECRET", uuid.uuid4().hex)
    env.setdefault("ORCHESTRATOR_INTERNAL_TOKEN", uuid.uuid4().hex)
    env.setdefault("OPERATOR_TOKEN", uuid.uuid4().hex)
    env.setdefault("SCOREBOARD_INTERNAL_TOKEN", uuid.uuid4().hex)
    return env


def _run(cmd: list[str], env: dict[str, str]) -> None:
    subprocess.run(cmd, check=True, env=env)


def _http_request(
    method: str, url: str, payload: dict | None = None, headers: dict | None = None
) -> dict:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            return {"status": resp.status, "body": json.loads(body) if body else {}}
    except error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode("utf-8")}


def _wait_for_ready(url: str, timeout_seconds: int = 120) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = _http_request("GET", url)
            if response["status"] == 200:
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"timeout waiting for {url}")


def _wait_for_artifacts(scenario_id: str, timeout_seconds: int = 120) -> Path:
    deadline = time.time() + timeout_seconds
    results_dir = Path("storage") / "scenarios" / scenario_id / "results"
    while time.time() < deadline:
        if results_dir.is_dir():
            score = results_dir / "score.json"
            verdict = results_dir / "verdict.sig"
            verdict_pub = results_dir / "verdict.pub"
            evidence_zst = results_dir / "evidence.tar.zst"
            evidence_gz = results_dir / "evidence.tar.gz"
            if score.exists() and verdict.exists() and verdict_pub.exists():
                if evidence_zst.exists() or evidence_gz.exists():
                    return results_dir
        time.sleep(2)
    raise RuntimeError("timeout waiting for scoring artifacts")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run staging smoke test")
    parser.add_argument("--skip-down", action="store_true", help="Leave compose running")
    args = parser.parse_args()

    env = _default_env()
    try:
        _run(_compose_cmd(["up", "-d", "--build"]), env)
        _wait_for_ready("http://localhost:8082/readyz")
        _wait_for_ready("http://localhost:8083/readyz")
        _wait_for_ready("http://localhost:8086/readyz")

        request_id = f"smoke-{uuid.uuid4().hex[:8]}"
        subject = f"user-{uuid.uuid4().hex[:6]}"
        spawn_payload = {
            "track": "netplus",
            "request_id": request_id,
            "subject": subject,
            "tier": "free",
        }
        spawn_headers = {
            "x-request-id": request_id,
            "x-client-id": subject,
        }
        spawn_response = _http_request(
            "POST", "http://localhost:8082/v1/spawn", spawn_payload, spawn_headers
        )
        if spawn_response["status"] != 200:
            raise RuntimeError(f"spawn failed: {spawn_response}")
        scenario_id = spawn_response["body"]["scenario_id"]

        completion_payload = {"completion_reason": "smoke_test"}
        completion_headers = {
            "x-internal-token": env["ORCHESTRATOR_INTERNAL_TOKEN"],
            "x-operator-token": env["OPERATOR_TOKEN"],
        }
        completion_response = _http_request(
            "POST",
            f"http://localhost:8083/internal/scenario/{scenario_id}/complete",
            completion_payload,
            completion_headers,
        )
        if completion_response["status"] != 200:
            raise RuntimeError(f"completion failed: {completion_response}")

        results_dir = _wait_for_artifacts(scenario_id)
        evidence_path = (
            results_dir / "evidence.tar.zst"
            if (results_dir / "evidence.tar.zst").exists()
            else results_dir / "evidence.tar.gz"
        )
        verify_cmd = [
            sys.executable,
            "scripts/verify_verdict.py",
            str(results_dir / "score.json"),
            str(evidence_path),
            str(results_dir / "verdict.sig"),
            str(results_dir / "verdict.pub"),
        ]
        _run(verify_cmd, env)
        print("Smoke test succeeded")
        return 0
    finally:
        if not args.skip_down:
            try:
                _run(_compose_cmd(["down", "--remove-orphans"]), env)
            except subprocess.CalledProcessError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
