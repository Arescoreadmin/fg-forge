from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

import requests
import yaml
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="FrostGate Forge Spawn Service")
logger = logging.getLogger("forge_spawn_service")

TRACKS = {"netplus", "ccna", "cissp"}
TRACK_TEMPLATE = {
    "netplus": "netplus.yaml",
    "ccna": "ccna.yaml",
    "cissp": "cissp.yaml",
}
TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", "/templates"))
REQUEST_CACHE: Dict[str, dict] = {}


class SpawnRequest(BaseModel):
    track: str = Field(..., description="Training track identifier")
    request_id: Optional[str] = Field(
        None, description="Client-supplied idempotency key"
    )


class SpawnResponse(BaseModel):
    request_id: str
    scenario_id: str
    access_url: str
    expires_at: str


def load_template(track: str) -> dict:
    template_name = TRACK_TEMPLATE[track]
    template_path = TEMPLATE_DIR / template_name
    if not template_path.exists():
        raise HTTPException(status_code=500, detail="template not found")
    with template_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def opa_allows(template: dict) -> None:
    opa_url = os.getenv("OPA_URL")
    if not opa_url:
        return

    try:
        response = requests.post(
            f"{opa_url}/v1/data/frostgate/forge/training/allow",
            json={"input": template},
            timeout=5,
        )
    except requests.RequestException as exc:
        logger.warning("OPA request failed: %s", exc)
        raise HTTPException(status_code=502, detail="OPA unavailable") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="OPA error")

    result = response.json().get("result")
    if result is not True:
        raise HTTPException(status_code=403, detail="OPA policy denied")


def record_billing(request_id: str, track: str) -> None:
    billing_mode = os.getenv("BILLING_MODE", "stub")
    logger.info("billing=%s request_id=%s track=%s", billing_mode, request_id, track)


def resolve_request_id(payload: SpawnRequest, request: Request) -> Optional[str]:
    header_name = os.getenv("REQUEST_ID_HEADER", "x-request-id")
    return payload.request_id or request.headers.get(header_name)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_spawn_service"}


@app.post("/v1/spawn", response_model=SpawnResponse)
def spawn_scenario(payload: SpawnRequest, request: Request) -> SpawnResponse:
    request_id = resolve_request_id(payload, request)
    if not request_id:
        raise HTTPException(status_code=400, detail="request_id required")

    if payload.track not in TRACKS:
        raise HTTPException(status_code=400, detail="unsupported track")

    if request_id in REQUEST_CACHE:
        return SpawnResponse(**REQUEST_CACHE[request_id])

    template = load_template(payload.track)
    opa_allows(template)
    record_billing(request_id, payload.track)

    scenario_id = f"scn-{uuid.uuid4().hex[:12]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    base_url = os.getenv("SPAWN_BASE_URL", "http://localhost:8082")
    access_url = f"{base_url}/access/{scenario_id}"  # placeholder for broker

    response = SpawnResponse(
        request_id=request_id,
        scenario_id=scenario_id,
        access_url=access_url,
        expires_at=expires_at,
    )

    REQUEST_CACHE[request_id] = response.model_dump()

    return response
