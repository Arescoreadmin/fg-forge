from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="FrostGate Forge Spawn Service")

TRACKS = {"netplus", "ccna", "cissp"}
REQUEST_CACHE: Dict[str, dict] = {}


class SpawnRequest(BaseModel):
    track: str = Field(..., description="Training track identifier")
    request_id: Optional[str] = Field(
        None, description="Client-supplied idempotency key"
    )


class SpawnResponse(BaseModel):
    scenario_id: str
    access_url: str
    expires_at: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_spawn_service"}


@app.post("/v1/spawn", response_model=SpawnResponse)
def spawn_scenario(
    payload: SpawnRequest,
    x_request_id: Optional[str] = Header(default=None),
) -> SpawnResponse:
    request_id = payload.request_id or x_request_id
    if payload.track not in TRACKS:
        raise HTTPException(status_code=400, detail="unsupported track")

    if request_id and request_id in REQUEST_CACHE:
        return SpawnResponse(**REQUEST_CACHE[request_id])

    scenario_id = f"scn-{uuid.uuid4().hex[:12]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    base_url = os.getenv("SPAWN_BASE_URL", "http://localhost:8082")
    access_url = f"{base_url}/access/{scenario_id}"  # placeholder for broker

    response = SpawnResponse(
        scenario_id=scenario_id, access_url=access_url, expires_at=expires_at
    )

    if request_id:
        REQUEST_CACHE[request_id] = response.model_dump()

    return response
