"""
FrostGate Forge Orchestrator Service.

Central coordinator for scenario lifecycle management. Validates templates,
enforces OPA policies, creates isolated networks, and manages container lifecycles.

Supports:
- ORCH_BACKEND=docker (dev/labs): Docker network + containers + ttyd + egress gateway join
- ORCH_BACKEND=k8s (prod): Kubernetes adapter path (no docker.sock needed)
"""

from __future__ import annotations

import asyncio
import base64
from collections import OrderedDict
from contextlib import asynccontextmanager, suppress
import contextvars
from datetime import UTC, datetime
from enum import Enum
import hashlib
import hmac
import importlib
import inspect
import json
import logging
import os
from pathlib import Path
import random
import time
from typing import Any
import uuid

import docker
from fastapi import APIRouter, FastAPI, HTTPException, Request
import httpx
import nats
from nats.js.api import ConsumerConfig, DeliverPolicy
from pydantic import BaseModel, Field
import yaml


# -----------------------------------------------------------------------------
# Config helpers
# -----------------------------------------------------------------------------
def cfg_orch_backend() -> str:
    return os.getenv("ORCH_BACKEND", "docker").lower()


def cfg_forge_env() -> str:
    return os.getenv("FORGE_ENV", "dev").lower()


def cfg_unit_tests() -> bool:
    return os.getenv("UNIT_TESTS") == "1"


def cfg_template_dir() -> Path:
    return Path(os.getenv("TEMPLATE_DIR", "/templates"))


def cfg_opa_url() -> str:
    return os.getenv("OPA_URL", "http://forge_opa:8181")


def cfg_nats_url() -> str:
    return os.getenv("NATS_URL", "nats://forge_nats:4222")


def cfg_scoreboard_url() -> str:
    return os.getenv("SCOREBOARD_URL", "http://forge_scoreboard:8080")


def cfg_storage_root() -> Path:
    return Path(os.getenv("STORAGE_ROOT", "storage"))


def cfg_scoreboard_asgi_import() -> str:
    return os.getenv("SCOREBOARD_ASGI_IMPORT", "services.scoreboard.app.main:app")


def cfg_http_max_retries() -> int:
    return int(os.getenv("HTTP_MAX_RETRIES", "2"))


def cfg_http_retry_base_delay() -> float:
    return float(os.getenv("HTTP_RETRY_BASE_DELAY_SECONDS", "0.2"))


def cfg_http_retry_jitter() -> float:
    return float(os.getenv("HTTP_RETRY_JITTER_SECONDS", "0.2"))


def cfg_circuit_breaker_cooldown() -> float:
    return float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))


# -----------------------------------------------------------------------------
# Gateway-only access config (ttyd + egress network join) for docker backend
# -----------------------------------------------------------------------------
def cfg_ttyd_enabled() -> bool:
    # default on for docker backend, off for k8s unless you build it there too
    return os.getenv("TTYD_ENABLED", "true").lower() == "true"


def cfg_ttyd_image() -> str:
    return os.getenv("TTYD_IMAGE", "tsl0922/ttyd:1.7.7")


def cfg_ttyd_port() -> int:
    return int(os.getenv("TTYD_PORT", "7681"))


def cfg_ttyd_shell() -> str:
    return os.getenv("TTYD_SHELL", "bash")


def cfg_gateway_container_name() -> str:
    return os.getenv("EGRESS_GATEWAY_CONTAINER_NAME", "forge_egress_gateway")


def cfg_ttyd_base_prefix() -> str:
    # Must match egress_gateway route prefix: /v1/cap/web_tty/{sid}
    return os.getenv("TTYD_BASE_PREFIX", "/v1/cap/web_tty")


# -----------------------------------------------------------------------------
# Routers (declare first; mount inside create_app())
# -----------------------------------------------------------------------------
router = APIRouter()
internal_router = APIRouter(prefix="/internal")

# Request correlation id (used by logger + middleware)
request_id_ctx = contextvars.ContextVar("request_id", default="-")


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
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
logger = logging.getLogger("forge_orchestrator")


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
NETWORK_PREFIX = "forge_scn_"
_sat_secret_warning_emitted = False


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class ScenarioStatus(str, Enum):
    PENDING = "pending"
    CREATING = "creating"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ScenarioState(BaseModel):
    scenario_id: str
    request_id: str
    track: str
    subject: str | None = None
    tenant_id: str | None = None
    tier: str | None = None
    retention_days: int | None = None
    status: ScenarioStatus = ScenarioStatus.PENDING
    network_id: str | None = None
    containers: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    completion_reason: str | None = None
    error: str | None = None


class CreateScenarioRequest(BaseModel):
    scenario_id: str
    template: str
    request_id: str
    tier: str


class CreateScenarioResponse(BaseModel):
    scenario_id: str
    status: ScenarioStatus
    network_id: str | None = None


class ScenarioCompletionRequest(BaseModel):
    completion_reason: str
    completion_timestamp: datetime | None = None


class SatClaims(BaseModel):
    jti: str
    exp: int
    iat: int
    track: str
    template_id: str
    subject: str
    tenant_id: str
    tier: str
    retention_days: int | None = None
    requested_limits: dict[str, int] | None = None
    scenario_id: str | None = None


# -----------------------------------------------------------------------------
# Replay protection (redis optional)
# -----------------------------------------------------------------------------
class ReplayProtector:
    def __init__(self) -> None:
        self._redis_client: Any | None = None
        self._cache: OrderedDict[str, int] = OrderedDict()
        self._max_size = int(os.getenv("SAT_REPLAY_CACHE_SIZE", "10000"))
        self._lock = asyncio.Lock()

    async def _get_redis(self) -> Any | None:
        if not os.getenv("REDIS_URL"):
            return None
        if self._redis_client is None:
            import redis.asyncio as redis

            self._redis_client = redis.from_url(
                os.getenv("REDIS_URL"),
                decode_responses=True,
            )
        return self._redis_client

    def _purge_expired(self, now: int) -> None:
        expired_keys = [key for key, exp in self._cache.items() if exp <= now]
        for key in expired_keys:
            self._cache.pop(key, None)

    async def check_and_store(self, jti: str, exp: int) -> bool:
        now = int(datetime.now(UTC).timestamp())
        ttl = exp - now
        if ttl <= 0:
            return False

        client = await self._get_redis()
        if client:
            try:
                key = f"sat:jti:{jti}"
                stored = await client.set(key, "1", nx=True, ex=ttl)
                return bool(stored)
            except Exception as exc:
                logger.warning("Redis replay check failed: %s", exc)
                return False

        async with self._lock:
            self._purge_expired(now)
            if jti in self._cache:
                return False
            self._cache[jti] = exp
            self._cache.move_to_end(jti)
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)
            return True


replay_protector = ReplayProtector()

# -----------------------------------------------------------------------------
# State (in-memory; consider redis/db for multi-replica prod)
# -----------------------------------------------------------------------------
scenarios: dict[str, ScenarioState] = {}

# -----------------------------------------------------------------------------
# Clients
# -----------------------------------------------------------------------------
docker_client: docker.DockerClient | None = None
nc: nats.NATS | None = None
js: Any = None


# -----------------------------------------------------------------------------
# Circuit breaker + http retry
# -----------------------------------------------------------------------------
class CircuitBreaker:
    def __init__(self, name: str, cooldown_seconds: float) -> None:
        self._name = name
        self._cooldown_seconds = cooldown_seconds
        self._last_failure = 0.0

    def is_open(self) -> bool:
        return (time.time() - self._last_failure) < self._cooldown_seconds

    def record_success(self) -> None:
        self._last_failure = 0.0

    def record_failure(self) -> None:
        self._last_failure = time.time()

    @property
    def name(self) -> str:
        return self._name


def _httpx_timeout() -> httpx.Timeout:
    connect = float(os.getenv("HTTP_CONNECT_TIMEOUT_SECONDS", "2.0"))
    read = float(os.getenv("HTTP_READ_TIMEOUT_SECONDS", "5.0"))
    return httpx.Timeout(connect=connect, read=read, write=read, pool=connect)


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


async def _request_with_retries(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    json_body: dict | None = None,
    headers: dict | None = None,
    breaker: CircuitBreaker | None = None,
) -> httpx.Response:
    if breaker and breaker.is_open():
        raise httpx.RequestError(f"{breaker.name} circuit breaker open")

    max_attempts = cfg_http_max_retries() + 1
    base_delay = cfg_http_retry_base_delay()
    jitter = cfg_http_retry_jitter()
    last_exc: Exception | None = None

    for attempt in range(max_attempts):
        try:
            response = await client.request(method, url, json=json_body, headers=headers)
            if response.status_code >= 500:
                raise httpx.RequestError(f"upstream {response.status_code}")
            if breaker:
                breaker.record_success()
            return response
        except httpx.RequestError as exc:
            last_exc = exc
            if breaker:
                breaker.record_failure()
            if attempt >= max_attempts - 1:
                break
            await _sleep(base_delay + random.uniform(0, jitter))

    raise httpx.RequestError("request failed") from last_exc


_opa_breaker = CircuitBreaker("opa", cfg_circuit_breaker_cooldown())
_scoreboard_breaker = CircuitBreaker("scoreboard", cfg_circuit_breaker_cooldown())
_egress_breaker = CircuitBreaker("egress_gateway", cfg_circuit_breaker_cooldown())


# -----------------------------------------------------------------------------
# Scoreboard client
# -----------------------------------------------------------------------------
def _import_from_path(import_path: str) -> Any:
    """Import "module.sub:attr" and return attr."""
    if ":" not in import_path:
        raise ValueError("import path must be like 'pkg.mod:attr'")
    mod_name, attr_name = import_path.split(":", 1)
    mod = importlib.import_module(mod_name)
    try:
        return getattr(mod, attr_name)
    except AttributeError as exc:
        raise ImportError(f"Attribute '{attr_name}' not found in '{mod_name}'") from exc


def _scoreboard_client() -> httpx.AsyncClient:
    """In UNIT_TESTS=1, run scoreboard in-process via ASGITransport; otherwise use SCOREBOARD_URL."""
    if cfg_unit_tests():
        try:
            from httpx import ASGITransport  # type: ignore
        except Exception as exc:
            raise RuntimeError("httpx.ASGITransport unavailable; upgrade httpx") from exc

        import_path = cfg_scoreboard_asgi_import()
        try:
            asgi_app = _import_from_path(import_path)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to import SCOREBOARD_ASGI_IMPORT={import_path}: {exc}"
            ) from exc

        return httpx.AsyncClient(
            transport=ASGITransport(app=asgi_app),
            base_url="http://scoreboard",
            timeout=_httpx_timeout(),
        )

    return httpx.AsyncClient(base_url=cfg_scoreboard_url(), timeout=_httpx_timeout())


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------
def load_template(track: str) -> dict:
    """Load scenario template from filesystem."""
    template_dir = cfg_template_dir()
    candidates: list[Path] = []
    name = track

    if name.endswith((".yaml", ".yml")):
        candidates.append(template_dir / name)
    else:
        candidates.append(template_dir / f"{name}.yaml")
        candidates.append(template_dir / f"{name}.yml")

    for p in candidates:
        if p.exists():
            with p.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}

    if cfg_unit_tests():
        return {
            "id": track,
            "track": track,
            "assets": {
                "containers": [
                    {
                        "name": "trainer",
                        "image": "alpine:3.19",
                        "read_only": True,
                        "environment": {},
                    }
                ]
            },
        }

    raise HTTPException(status_code=404, detail=f"Template not found: {track}")


# -----------------------------------------------------------------------------
# SAT utilities
# -----------------------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _warn_sat_secret_alias() -> None:
    global _sat_secret_warning_emitted
    if not _sat_secret_warning_emitted:
        logger.warning("SAT_SECRET is deprecated; set SAT_HMAC_SECRET instead")
        _sat_secret_warning_emitted = True


def _get_sat_secret() -> str:
    sat_secret = os.getenv("SAT_HMAC_SECRET")
    if sat_secret:
        return sat_secret
    legacy_secret = os.getenv("SAT_SECRET")
    if legacy_secret:
        _warn_sat_secret_alias()
        return legacy_secret
    raise HTTPException(status_code=500, detail="SAT secret not configured")


def _parse_bearer_token(value: str) -> str | None:
    if not value:
        return None
    parts = value.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def verify_sat(token: str) -> SatClaims:
    try:
        header_encoded, payload_encoded, signature_encoded = token.split(".", 2)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid sat") from exc

    try:
        header = json.loads(_b64url_decode(header_encoded))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid sat") from exc

    if header.get("alg") != "HS256" or header.get("typ") != "SAT":
        raise HTTPException(status_code=401, detail="invalid sat")

    signing_input = f"{header_encoded}.{payload_encoded}".encode()
    expected_signature = hmac.new(
        _get_sat_secret().encode("utf-8"), signing_input, "sha256"
    ).digest()
    expected_encoded = _b64url_encode(expected_signature)
    if not hmac.compare_digest(expected_encoded, signature_encoded):
        raise HTTPException(status_code=401, detail="invalid sat")

    try:
        payload = SatClaims.model_validate(json.loads(_b64url_decode(payload_encoded)))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid sat") from exc

    now = int(datetime.now(UTC).timestamp())
    if payload.iat > payload.exp:
        raise HTTPException(status_code=401, detail="invalid sat")
    if payload.exp < now:
        raise HTTPException(status_code=401, detail="sat expired")

    return payload


async def enforce_sat(
    app: FastAPI,
    token: str | None,
    scenario_id: str | None,
    track: str | None,
    template_id: str | None,
    tier: str | None,
) -> SatClaims:
    """Validate SAT, enforce constraints, prevent replay."""
    if not token:
        raise HTTPException(status_code=401, detail="sat required")

    claims = verify_sat(token)
    if not claims.subject or not claims.tenant_id:
        raise HTTPException(status_code=401, detail="sat missing subject or tenant")

    if scenario_id and claims.scenario_id and claims.scenario_id != scenario_id:
        raise HTTPException(status_code=403, detail="sat scenario mismatch")
    if track and claims.track != track:
        raise HTTPException(status_code=403, detail="sat track mismatch")
    if template_id and claims.template_id != template_id:
        raise HTTPException(status_code=403, detail="sat template mismatch")
    if tier and claims.tier != tier:
        raise HTTPException(status_code=403, detail="sat tier mismatch")

    stored = await app.state.replay_protector.check_and_store(claims.jti, claims.exp)
    if not stored:
        raise HTTPException(status_code=401, detail="sat replayed")

    return claims


async def _call_enforce_sat(
    app_obj: Any,
    token: str | None,
    scenario_id: str | None,
    track: str | None,
    template_id: str | None,
    tier: str | None,
) -> SatClaims:
    sig = inspect.signature(enforce_sat)
    params = list(sig.parameters.values())
    names = {p.name for p in params}

    kwargs: dict[str, Any] = {}
    if "app" in names:
        kwargs["app"] = app_obj
    if "token" in names:
        kwargs["token"] = token
    if "scenario_id" in names:
        kwargs["scenario_id"] = scenario_id
    if "track" in names:
        kwargs["track"] = track
    if "template_id" in names:
        kwargs["template_id"] = template_id
    elif "template" in names:
        kwargs["template"] = template_id
    if "tier" in names:
        kwargs["tier"] = tier

    try:
        return await enforce_sat(**kwargs)  # type: ignore[misc]
    except TypeError:
        arity = len(
            [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        )
        if arity >= 6:
            return await enforce_sat(app_obj, token, scenario_id, track, template_id, tier)  # type: ignore[misc]
        return await enforce_sat(token, scenario_id, track, template_id, tier)  # type: ignore[misc]


# -----------------------------------------------------------------------------
# Internal auth
# -----------------------------------------------------------------------------
def _require_internal_auth(request: Request) -> None:
    expected = os.getenv("ORCHESTRATOR_INTERNAL_TOKEN")
    if not expected:
        logger.error("ORCHESTRATOR_INTERNAL_TOKEN not configured")
        raise HTTPException(status_code=500, detail="internal auth not configured")
    token = request.headers.get("x-internal-token", "")
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="internal auth required")


def _require_operator_auth(request: Request) -> None:
    expected = os.getenv("OPERATOR_TOKEN")
    if not expected:
        logger.error("OPERATOR_TOKEN not configured")
        raise HTTPException(status_code=500, detail="operator auth not configured")
    token = request.headers.get("x-operator-token", "")
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="operator auth required")


# -----------------------------------------------------------------------------
# OPA + readiness
# -----------------------------------------------------------------------------
def _normalize_plan(tier: str | None) -> str | None:
    if not tier:
        return None
    return tier.upper()


def _build_opa_input(template: dict, claims: SatClaims) -> dict:
    payload = dict(template)
    payload["plan"] = _normalize_plan(claims.tier)
    payload["retention_days"] = claims.retention_days
    payload["subject"] = claims.subject
    payload["tenant_id"] = claims.tenant_id
    return payload


async def check_opa_policy(input_payload: dict) -> tuple[bool, str | None]:
    """Query OPA for policy decision."""
    if cfg_unit_tests():
        return True, None

    opa_url = cfg_opa_url()
    async with httpx.AsyncClient(timeout=_httpx_timeout()) as client:
        try:
            response = await _request_with_retries(
                client,
                "POST",
                f"{opa_url}/v1/data/frostgate/forge/training/allow",
                json_body={"input": input_payload},
                breaker=_opa_breaker,
            )

            if response.status_code >= 400:
                return False, f"OPA error: {response.status_code}"

            result = response.json()
            allowed = result.get("result", False)
            if not allowed:
                return False, "Policy denied"

            return True, None

        except httpx.RequestError as e:
            logger.warning("OPA request failed: %s", e)
            return False, f"OPA unavailable: {e}"
        except Exception:
            logger.exception("orchestrator: unhandled error in OPA policy check")
            raise


async def _check_opa_ready() -> None:
    opa_url = cfg_opa_url()
    async with httpx.AsyncClient(timeout=_httpx_timeout()) as client:
        try:
            response = await _request_with_retries(
                client, "GET", f"{opa_url}/health", breaker=_opa_breaker
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=503, detail=f"opa unavailable: {exc}") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail=f"opa unhealthy: {response.status_code}")


def _read_only_required() -> bool:
    if os.getenv("READ_ONLY_REQUIRED", "").lower() == "true":
        return True
    return cfg_forge_env() in {"staging", "prod", "production"}


def _check_read_only_fs() -> None:
    if not _read_only_required():
        return
    probe_path = Path("/.forge_read_only_probe")
    try:
        probe_path.write_text("probe", encoding="utf-8")
    except OSError:
        return
    else:
        with suppress(OSError):
            probe_path.unlink()
        raise HTTPException(status_code=503, detail="filesystem not read-only")


async def _check_egress_gateway() -> None:
    egress_url = os.getenv("EGRESS_GATEWAY_URL")
    if not egress_url:
        return
    expected = os.getenv("EGRESS_DRY_RUN_EXPECTED")
    if expected is None:
        expected = "true" if cfg_forge_env() == "dev" else "false"

    async with httpx.AsyncClient(timeout=_httpx_timeout()) as client:
        try:
            response = await _request_with_retries(
                client, "GET", f"{egress_url}/readyz", breaker=_egress_breaker
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=503, detail=f"egress gateway unavailable: {exc}"
            ) from exc

    if response.status_code >= 400:
        raise HTTPException(
            status_code=503, detail=f"egress gateway unhealthy: {response.status_code}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="egress gateway invalid response") from exc

    if str(payload.get("dry_run", "")).lower() != expected.lower():
        raise HTTPException(status_code=503, detail="egress gateway config mismatch")


# -----------------------------------------------------------------------------
# Scoreboard trigger
# -----------------------------------------------------------------------------
async def _trigger_scoreboard(
    scenario_id: str,
    track: str,
    completion_reason: str,
    completed_at: datetime,
    subject: str | None,
    tenant_id: str | None,
    tier: str | None,
    retention_days: int | None,
    correlation_id: str | None,
) -> None:
    token = os.getenv("SCOREBOARD_INTERNAL_TOKEN")
    if not token and cfg_unit_tests():
        token = "test-scoreboard"
    if not token:
        raise RuntimeError("SCOREBOARD_INTERNAL_TOKEN not configured")

    payload = {
        "scenario_id": scenario_id,
        "track": track,
        "completion_reason": completion_reason,
        "completed_at": completed_at.isoformat(),
        "subject": subject,
        "tenant_id": tenant_id,
        "plan": tier,
        "retention_days": retention_days,
    }
    headers = {"x-internal-token": token}
    if correlation_id:
        headers["x-request-id"] = correlation_id

    async with _scoreboard_client() as client:
        response = await _request_with_retries(
            client,
            "POST",
            f"/internal/scenario/{scenario_id}/score",
            json_body=payload,
            headers=headers,
            breaker=_scoreboard_breaker,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"scoreboard error {response.status_code}: {response.text}")


# -----------------------------------------------------------------------------
# Audit chain
# -----------------------------------------------------------------------------
def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _audit_payload(entry: dict[str, Any]) -> bytes:
    payload = dict(entry)
    payload.pop("entry_hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _audit_path(scenario_id: str) -> Path:
    return cfg_storage_root() / "scenarios" / scenario_id / "results" / "audit.jsonl"


def append_audit_event(
    app: FastAPI,
    scenario_id: str,
    event_type: str,
    actor: str,
    correlation_id: str,
    details: dict[str, Any],
) -> None:
    # app currently unused (kept for future: per-tenant storage routing, etc.)
    audit_path = _audit_path(scenario_id)
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if audit_path.exists():
        last_line = ""
        with audit_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                last_line = line
        if last_line:
            try:
                prev_hash = json.loads(last_line).get("entry_hash", prev_hash)
            except json.JSONDecodeError:
                prev_hash = "0" * 64

    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "scenario_id": scenario_id,
        "event_type": event_type,
        "actor": actor,
        "correlation_id": correlation_id,
        "details": details,
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = _hash_bytes(_audit_payload(entry))

    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")


# -----------------------------------------------------------------------------
# Backend: Docker orchestration
# -----------------------------------------------------------------------------
def _production_guardrail_for_docker() -> None:
    if cfg_orch_backend() != "docker":
        return
    if cfg_forge_env() in {"prod", "production"} and os.getenv("ALLOW_DOCKER_IN_PROD", "").lower() != "true":
        raise RuntimeError(
            "docker backend is not allowed in production by default. "
            "Set ORCH_BACKEND=k8s, or explicitly set ALLOW_DOCKER_IN_PROD=true (not recommended)."
        )


def get_docker_client() -> docker.DockerClient:
    global docker_client
    if docker_client is None:
        docker_client = docker.from_env()
        if not cfg_unit_tests():
            docker_client.ping()
    return docker_client


def _scenario_network_name(scenario_id: str) -> str:
    return f"{NETWORK_PREFIX}{scenario_id}"


def docker_create_scenario_network(scenario_id: str) -> str:
    client = get_docker_client()
    network_name = _scenario_network_name(scenario_id)
    network = client.networks.create(
        name=network_name,
        driver="bridge",
        internal=True,
        labels={
            "forge.scenario_id": scenario_id,
            "forge.created_at": datetime.now(UTC).isoformat(),
            "forge.managed": "true",
        },
    )
    logger.info("Created network %s for scenario %s", network_name, scenario_id)
    return network.id


def docker_launch_scenario_containers(scenario_id: str, network_id: str, template: dict) -> list[str]:
    client = get_docker_client()
    container_ids: list[str] = []

    assets = template.get("assets", {})
    containers_spec = assets.get("containers", [])

    for container_spec in containers_spec:
        name = container_spec.get("name", f"container-{uuid.uuid4().hex[:8]}")
        image = container_spec.get("image", "alpine:3.19")
        read_only = container_spec.get("read_only", True)
        environment = container_spec.get("environment", {})

        container_name = f"forge_{scenario_id}_{name}"

        def _run() -> docker.models.containers.Container:
            return client.containers.run(
                image=image,
                name=container_name,
                detach=True,
                read_only=read_only,
                environment=environment,
                network=network_id,
                labels={
                    "forge.scenario_id": scenario_id,
                    "forge.container_name": name,
                    "forge.managed": "true",
                },
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=os.getenv("SCENARIO_MEM_LIMIT", "512m"),
                cpu_quota=int(os.getenv("SCENARIO_CPU_QUOTA", "50000")),
                command="sleep infinity" if "alpine" in image else None,
            )

        try:
            container = _run()
            container_ids.append(container.id)
            logger.info(
                "Launched container %s (%s) for scenario %s", container_name, image, scenario_id
            )
        except docker.errors.ImageNotFound:
            logger.warning("Image %s not found, pulling...", image)
            client.images.pull(image)
            container = _run()
            container_ids.append(container.id)
        except docker.errors.APIError as e:
            logger.error("Failed to launch container %s: %s", name, e)
            raise

    return container_ids


def docker_cleanup_scenario(scenario_id: str) -> None:
    client = get_docker_client()

    containers = client.containers.list(
        all=True, filters={"label": f"forge.scenario_id={scenario_id}"}
    )
    for container in containers:
        try:
            container.stop(timeout=5)
            container.remove(force=True)
            logger.info("Removed container %s", container.name)
        except docker.errors.APIError as e:
            logger.warning("Failed to remove container %s: %s", container.name, e)

    networks = client.networks.list(filters={"label": f"forge.scenario_id={scenario_id}"})
    for network in networks:
        try:
            network.remove()
            logger.info("Removed network %s", network.name)
        except docker.errors.APIError as e:
            logger.warning("Failed to remove network %s: %s", network.name, e)


def _safe_get_container(client: docker.DockerClient, name: str):
    try:
        return client.containers.get(name)
    except Exception:
        return None


def docker_connect_gateway_to_network(scenario_id: str, network_id: str) -> None:
    client = get_docker_client()
    gw_name = cfg_gateway_container_name()
    gw = _safe_get_container(client, gw_name)
    if not gw:
        logger.warning("Gateway container not found: %s (skipping network join)", gw_name)
        return

    net = client.networks.get(network_id)
    try:
        net.connect(gw, aliases=[f"gw-{scenario_id}"])
        logger.info("Connected gateway %s to network %s for scenario %s", gw_name, net.name, scenario_id)
    except docker.errors.APIError as exc:
        msg = str(exc).lower()
        if "already exists" in msg or "already connected" in msg:
            logger.info("Gateway already connected to network %s for scenario %s", net.name, scenario_id)
            return
        raise


def docker_launch_ttyd_container(scenario_id: str, network_id: str) -> str:
    """
    Launch per-scenario ttyd inside the scenario network (no host ports).
    ttyd base-path must match gateway route prefix:
      /v1/cap/web_tty/<scenario_id>
    """
    client = get_docker_client()
    ttyd_name = f"forge_ttyd_{scenario_id}"
    base_path = f"{cfg_ttyd_base_prefix().rstrip('/')}/{scenario_id}"

    existing = _safe_get_container(client, ttyd_name)
    if existing:
        with suppress(Exception):
            existing.reload()
        if getattr(existing, "status", "") != "running":
            with suppress(Exception):
                existing.start()
        logger.info("ttyd already exists for scenario %s: %s", scenario_id, ttyd_name)
        return existing.id

    def _run():
        return client.containers.run(
            image=cfg_ttyd_image(),
            name=ttyd_name,
            detach=True,
            read_only=True,
            network=network_id,
            hostname="ttyd",  # gateway resolves "ttyd" in scenario network
            labels={
                "forge.scenario_id": scenario_id,
                "forge.container_name": "ttyd",
                "forge.managed": "true",
            },
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            tmpfs={"/tmp": "rw,nosuid,nodev,size=64m"},
            ports={},  # explicit: no host port mappings
            command=[
                "ttyd",
                "--port", str(cfg_ttyd_port()),
                "--base-path", base_path,
                cfg_ttyd_shell(),
            ],
        )

    try:
        c = _run()
        logger.info("Launched ttyd %s for scenario %s (base_path=%s)", ttyd_name, scenario_id, base_path)
        return c.id
    except docker.errors.ImageNotFound:
        logger.warning("ttyd image %s not found, pulling...", cfg_ttyd_image())
        client.images.pull(cfg_ttyd_image())
        c = _run()
        logger.info("Launched ttyd %s for scenario %s (base_path=%s)", ttyd_name, scenario_id, base_path)
        return c.id


# -----------------------------------------------------------------------------
# Scenario completion
# -----------------------------------------------------------------------------
async def complete_scenario(
    scenario_id: str,
    completion_reason: str,
    completion_timestamp: datetime | None = None,
) -> ScenarioState:
    scenarios_map: dict[str, ScenarioState] = app.state.scenarios
    if scenario_id not in scenarios_map:
        raise HTTPException(status_code=404, detail="Scenario not found")

    state = scenarios_map[scenario_id]
    completed_at = completion_timestamp or datetime.now(UTC)
    state.completed_at = completed_at
    state.completion_reason = completion_reason
    state.updated_at = datetime.now(UTC)

    logger.info(
        "Scenario completed: scenario_id=%s reason=%s completed_at=%s",
        scenario_id,
        completion_reason,
        completed_at.isoformat(),
    )

    try:
        append_audit_event(
            app,
            scenario_id=scenario_id,
            event_type="scenario.complete",
            actor="operator",
            correlation_id=request_id_ctx.get(),
            details={
                "reason": completion_reason,
                "subject": state.subject,
                "tenant_id": state.tenant_id,
            },
        )
        await _trigger_scoreboard(
            scenario_id,
            state.track,
            completion_reason,
            completed_at,
            state.subject,
            state.tenant_id,
            state.tier,
            state.retention_days,
            request_id_ctx.get(),
        )
        state.status = ScenarioStatus.COMPLETED
    except Exception as exc:
        state.status = ScenarioStatus.COMPLETED_WITH_ERRORS
        state.error = str(exc)
        logger.error("Scenario %s scoring failed: %s", scenario_id, exc)
        raise HTTPException(status_code=502, detail=f"scoring failed: {exc}") from exc

    return state


# -----------------------------------------------------------------------------
# NATS spawn consumer
# -----------------------------------------------------------------------------
async def process_spawn_request(msg: Any) -> None:
    """Process incoming spawn request from NATS."""
    try:
        data = json.loads(msg.data.decode("utf-8"))

        scenario_id = data.get("scenario_id")
        track = data.get("track")
        request_id = data.get("request_id")
        tier = data.get("tier")
        sat = data.get("sat")
        correlation_id = data.get("correlation_id") or request_id or "-"

        if not scenario_id or not track or not tier:
            logger.warning("Spawn request missing scenario_id, track, or tier")
            await msg.ack()
            return

        request_id_ctx.set(correlation_id)

        try:
            template_id = data.get("template_id") or track
            claims = await _call_enforce_sat(app, sat, scenario_id, track, template_id, tier)
        except HTTPException as exc:
            logger.warning("Spawn request denied: %s", exc.detail)
            await msg.ack()
            return
        except Exception as exc:
            logger.exception("Error processing spawn request: %s", exc)
            await msg.ack()
            return

        logger.info(
            "Processing spawn request: scenario_id=%s track=%s request_id=%s",
            scenario_id,
            track,
            request_id,
        )

        template = load_template(track)

        allowed, reason = await check_opa_policy(_build_opa_input(template, claims))
        if not allowed:
            logger.warning("Scenario %s denied by policy: %s", scenario_id, reason)
            await msg.ack()
            return

        state = ScenarioState(
            scenario_id=scenario_id,
            request_id=request_id,
            track=track,
            subject=claims.subject,
            tenant_id=claims.tenant_id,
            tier=_normalize_plan(claims.tier),
            retention_days=claims.retention_days,
            status=ScenarioStatus.CREATING,
        )
        store: dict[str, ScenarioState] = app.state.scenarios
        store[scenario_id] = state

        append_audit_event(
            app,
            scenario_id=scenario_id,
            event_type="scenario.create",
            actor=claims.subject,
            correlation_id=correlation_id,
            details={"track": track, "tenant_id": claims.tenant_id, "backend": cfg_orch_backend()},
        )

        # NATS path: only implemented for docker backend today
        if cfg_orch_backend() == "k8s":
            logger.warning("spawn.request received but ORCH_BACKEND=k8s; ignoring (use API path)")
            await msg.ack()
            return

        _production_guardrail_for_docker()

        network_id = docker_create_scenario_network(scenario_id)
        state.network_id = network_id

        container_ids = docker_launch_scenario_containers(scenario_id, network_id, template)

        # Gateway-only access: ttyd + gateway join
        ttyd_id: str | None = None
        if cfg_ttyd_enabled():
            ttyd_id = docker_launch_ttyd_container(scenario_id, network_id)
            docker_connect_gateway_to_network(scenario_id, network_id)

        state.containers
