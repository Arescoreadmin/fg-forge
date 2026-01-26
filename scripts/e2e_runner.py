from dataclasses import dataclass
import os
import sys
import time

import httpx


@dataclass(frozen=True)
class ServiceUrls:
    spawn: str
    orchestrator: str
    scoreboard: str


def _env_urls() -> ServiceUrls:
    return ServiceUrls(
        spawn=os.getenv("SPAWN_URL", "http://spawn_service:8080"),
        orchestrator=os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8080"),
        scoreboard=os.getenv("SCOREBOARD_URL", "http://scoreboard:8080"),
    )


def wait_ready(url: str, timeout_seconds: float = 30.0) -> None:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            response = httpx.get(f"{url}/readyz", timeout=2.0)
            if response.status_code == 200:
                return
            last_error = f"{response.status_code} {response.text}"
        except httpx.RequestError as exc:
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"Service {url} not ready: {last_error}")


def run() -> int:
    urls = _env_urls()
    request_id = "req-e2e-001"
    scenario_id = "scn-e2e-compose"
    subject = "user-e2e"

    internal_token = os.getenv("ORCHESTRATOR_INTERNAL_TOKEN", "orch-token")
    operator_token = os.getenv("OPERATOR_TOKEN", "operator-token")

    wait_ready(urls.spawn)
    wait_ready(urls.orchestrator)
    wait_ready(urls.scoreboard)

    spawn_response = httpx.post(
        f"{urls.spawn}/api/spawn",
        json={
            "track": "netplus",
            "request_id": request_id,
            "subject": subject,
            "tier": "free",
            "scenario_id": scenario_id,
        },
        headers={"x-request-id": request_id, "x-tenant-id": subject},
        timeout=10.0,
    )
    if spawn_response.status_code >= 400:
        raise RuntimeError(f"spawn failed: {spawn_response.text}")

    completion_response = httpx.post(
        f"{urls.orchestrator}/internal/scenario/{scenario_id}/complete",
        json={"completion_reason": "finished"},
        headers={
            "x-request-id": request_id,
            "x-internal-token": internal_token,
            "x-operator-token": operator_token,
        },
        timeout=10.0,
    )
    if completion_response.status_code >= 400:
        raise RuntimeError(f"completion failed: {completion_response.text}")

    score_response = httpx.get(f"{urls.scoreboard}/v1/scores/{scenario_id}", timeout=10.0)
    if score_response.status_code >= 400:
        raise RuntimeError(f"score lookup failed: {score_response.text}")

    audit_response = httpx.get(f"{urls.scoreboard}/v1/audit/{scenario_id}/verify", timeout=10.0)
    if audit_response.status_code >= 400:
        raise RuntimeError(f"audit lookup failed: {audit_response.text}")

    score_body = score_response.json()
    audit_body = audit_response.json()

    print(f"scenario_id={score_body['scenario_id']}")
    print(f"score={score_body['score']['score']}")
    print(f"evidence_sha256={score_body['evidence_sha256']}")
    print(f"audit_ok={audit_body['audit_ok']}")

    if not audit_body.get("audit_ok"):
        raise RuntimeError("audit chain verification failed")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except Exception as exc:  # pragma: no cover - runner exit path
        print(str(exc), file=sys.stderr)
        raise
