from __future__ import annotations

import base64
import contextvars
import hmac
import json
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

request_id_ctx = contextvars.ContextVar("request_id", default="-")


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": request_id_ctx.get(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())


configure_logging()

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
_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET")
if not _TOKEN_SECRET:
    _TOKEN_SECRET = uuid.uuid4().hex
    logger.warning("ACCESS_TOKEN_SECRET not set; generated ephemeral secret")


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = (
        request.headers.get("x-request-id")
        or request.headers.get("x-correlation-id")
        or str(uuid.uuid4())
    )
    token = request_id_ctx.set(request_id)
    response = await call_next(request)
    request_id_ctx.reset(token)
    response.headers["x-request-id"] = request_id
    return response


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_access_token(payload: AccessTokenPayload) -> str:
    payload_json = payload.model_dump_json()
    payload_encoded = _b64url_encode(payload_json.encode("utf-8"))
    signature = hmac.new(
        _TOKEN_SECRET.encode("utf-8"), payload_encoded.encode("utf-8"), "sha256"
    ).digest()
    signature_encoded = _b64url_encode(signature)
    return f"{payload_encoded}.{signature_encoded}"


def verify_access_token(token: str) -> AccessTokenPayload:
    try:
        payload_encoded, signature_encoded = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc

    expected_signature = hmac.new(
        _TOKEN_SECRET.encode("utf-8"), payload_encoded.encode("utf-8"), "sha256"
    ).digest()
    expected_encoded = _b64url_encode(expected_signature)
    if not hmac.compare_digest(expected_encoded, signature_encoded):
        raise HTTPException(status_code=401, detail="invalid token")

    try:
        payload = AccessTokenPayload.model_validate(
            json.loads(_b64url_decode(payload_encoded))
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc

    expires_at = datetime.fromisoformat(payload.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="token expired")

    return payload


def verify_spawn_authorization(token: str) -> SpawnAuthorizationPayload:
    try:
        payload_encoded, signature_encoded = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid spawn authorization") from exc

    sat_secret = os.getenv("SAT_SECRET") or _TOKEN_SECRET
    expected_signature = hmac.new(
        sat_secret.encode("utf-8"), payload_encoded.encode("utf-8"), "sha256"
    ).digest()
    expected_encoded = _b64url_encode(expected_signature)
    if not hmac.compare_digest(expected_encoded, signature_encoded):
        raise HTTPException(status_code=401, detail="invalid spawn authorization")

    try:
        payload = SpawnAuthorizationPayload.model_validate(
            json.loads(_b64url_decode(payload_encoded))
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid spawn authorization") from exc

    expires_at = datetime.fromisoformat(payload.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="spawn authorization expired")

    return payload


def parse_bearer_token(value: str) -> Optional[str]:
    if not value:
        return None
    parts = value.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def enforce_spawn_authorization(request: Request) -> Optional[SpawnAuthorizationPayload]:
    sat_required = os.getenv("SAT_REQUIRED", "false").lower() == "true"
    token = request.headers.get("x-sat")
    if not token:
        token = parse_bearer_token(request.headers.get("authorization", ""))

    if not token:
        if sat_required:
            raise HTTPException(status_code=401, detail="spawn authorization required")
        return None

    return verify_spawn_authorization(token)


class SpawnRequest(BaseModel):
    track: str = Field(..., description="Training track identifier")
    request_id: Optional[str] = Field(
        None, description="Client-supplied idempotency key"
    )


class SpawnResponse(BaseModel):
    request_id: str
    scenario_id: str
    access_url: str
    access_token: str
    expires_at: str


class AccessTokenPayload(BaseModel):
    scenario_id: str
    request_id: str
    track: str
    expires_at: str


class SpawnAuthorizationPayload(BaseModel):
    subject: str
    issued_at: str
    expires_at: str
    tenant_id: Optional[str] = None
    scope: Optional[str] = None


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


def build_spawn_response(payload: SpawnRequest, request: Request) -> SpawnResponse:
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
    token_payload = AccessTokenPayload(
        scenario_id=scenario_id,
        request_id=request_id,
        track=payload.track,
        expires_at=expires_at,
    )
    access_token = generate_access_token(token_payload)
    access_url = f"{base_url}/v1/access/{scenario_id}?token={access_token}"

    response = SpawnResponse(
        request_id=request_id,
        scenario_id=scenario_id,
        access_url=access_url,
        access_token=access_token,
        expires_at=expires_at,
    )

    REQUEST_CACHE[request_id] = response.model_dump()

    return response


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_spawn_service"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_spawn_service"}


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "service": "forge_spawn_service"}


@app.post("/v1/spawn", response_model=SpawnResponse)
def spawn_scenario(payload: SpawnRequest, request: Request) -> SpawnResponse:
    enforce_spawn_authorization(request)
    return build_spawn_response(payload, request)


@app.post("/api/spawn", response_model=SpawnResponse)
def spawn_scenario_api(payload: SpawnRequest, request: Request) -> SpawnResponse:
    enforce_spawn_authorization(request)
    return build_spawn_response(payload, request)


@app.get("/v1/access/{scenario_id}")
def access_scenario(scenario_id: str, request: Request) -> dict:
    token = request.query_params.get("token") or request.headers.get("x-access-token")
    if not token:
        raise HTTPException(status_code=401, detail="token required")

    payload = verify_access_token(token)
    if payload.scenario_id != scenario_id:
        raise HTTPException(status_code=403, detail="token mismatch")

    return {
        "scenario_id": payload.scenario_id,
        "request_id": payload.request_id,
        "track": payload.track,
        "expires_at": payload.expires_at,
    }
