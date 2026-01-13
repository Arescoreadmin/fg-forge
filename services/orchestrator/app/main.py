"""FrostGate Forge Orchestrator Service.

Central coordinator for scenario lifecycle management. Validates templates,
enforces OPA policies, creates isolated networks, and manages container lifecycles.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hmac
import hashlib
import json
import logging
import os
import random
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import docker
import httpx
import nats
import yaml
from fastapi import APIRouter, FastAPI, HTTPException, Request
from nats.js.api import ConsumerConfig, DeliverPolicy
from pydantic import BaseModel, Field

request_id_ctx = contextvars.ContextVar("request_id", default="-")
router = APIRouter()


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
logger = logging.getLogger("forge_orchestrator")
_sat_secret_warning_emitted = False

NETWORK_PREFIX = "forge_scn_"


@dataclass(frozen=True)
class OrchestratorConfig:
    template_dir: Path
    opa_url: str
    nats_url: str
    scoreboard_url: str
    scoreboard_app: FastAPI | None
    storage_root: Path
    policy_backend: str
    container_backend: str
    event_bus_backend: str
    storage_backend: str

    @classmethod
    def from_env(cls) -> "OrchestratorConfig":
        return cls(
            template_dir=Path(os.getenv("TEMPLATE_DIR", "/templates")),
            opa_url=os.getenv("OPA_URL", "http://forge_opa:8181"),
            nats_url=os.getenv("NATS_URL", "nats://forge_nats:4222"),
            scoreboard_url=os.getenv("SCOREBOARD_URL", "http://forge_scoreboard:8080"),
            scoreboard_app=None,
            storage_root=Path(os.getenv("STORAGE_ROOT", "storage")),
            policy_backend=os.getenv("POLICY_BACKEND", "opa"),
            container_backend=os.getenv("CONTAINER_RUNTIME", "docker"),
            event_bus_backend=os.getenv("EVENT_BUS_BACKEND", "nats"),
            storage_backend=os.getenv("STORAGE_BACKEND", "fs"),
        )


class PolicyEvaluator:
    async def allow(self, input_payload: dict) -> tuple[bool, str | None]:
        raise NotImplementedError

    async def ready(self) -> None:
        return None


class OpaPolicyEvaluator(PolicyEvaluator):
    def __init__(self, opa_url: str) -> None:
        self._opa_url = opa_url.rstrip("/")

    async def allow(self, input_payload: dict) -> tuple[bool, str | None]:
        async with httpx.AsyncClient(timeout=_httpx_timeout()) as client:
            try:
                response = await _request_with_retries(
                    client,
                    "POST",
                    f"{self._opa_url}/v1/data/frostgate/forge/training/allow",
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

    async def ready(self) -> None:
        async with httpx.AsyncClient(timeout=_httpx_timeout()) as client:
            try:
                response = await _request_with_retries(
                    client,
                    "GET",
                    f"{self._opa_url}/health",
                    breaker=_opa_breaker,
                )
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=503, detail=f"opa unavailable: {exc}"
                ) from exc
        if response.status_code >= 400:
            raise HTTPException(
                status_code=503, detail=f"opa unhealthy: {response.status_code}"
            )


class AllowAllPolicyEvaluator(PolicyEvaluator):
    async def allow(self, input_payload: dict) -> tuple[bool, str | None]:
        return True, None


class ContainerRuntime:
    def create_network(self, scenario_id: str) -> str:
        raise NotImplementedError

    def launch_containers(
        self, scenario_id: str, network_id: str, template: dict
    ) -> list[str]:
        raise NotImplementedError

    def cleanup(self, scenario_id: str) -> None:
        raise NotImplementedError


class DockerContainerRuntime(ContainerRuntime):
    def __init__(self) -> None:
        self._client: docker.DockerClient | None = None

    def _get_client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def create_network(self, scenario_id: str) -> str:
        client = self._get_client()
        network_name = f"{NETWORK_PREFIX}{scenario_id}"

        network = client.networks.create(
            name=network_name,
            driver="bridge",
            internal=True,
            labels={
                "forge.scenario_id": scenario_id,
                "forge.created_at": datetime.now(timezone.utc).isoformat(),
                "forge.managed": "true",
            },
        )
        logger.info("Created network %s for scenario %s", network_name, scenario_id)
        return network.id

    def launch_containers(
        self, scenario_id: str, network_id: str, template: dict
    ) -> list[str]:
        client = self._get_client()
        container_ids = []

        assets = template.get("assets", {})
        containers_spec = assets.get("containers", [])

        for container_spec in containers_spec:
            name = container_spec.get("name", f"container-{uuid.uuid4().hex[:8]}")
            image = container_spec.get("image", "alpine:3.19")
            read_only = container_spec.get("read_only", True)
            environment = container_spec.get("environment", {})

            container_name = f"forge_{scenario_id}_{name}"

            try:
                container = client.containers.run(
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
                    mem_limit="512m",
                    cpu_quota=50000,
                    command="sleep infinity" if "alpine" in image else None,
                )
                container_ids.append(container.id)
            except docker.errors.ImageNotFound:
                logger.warning("Image %s not found, pulling...", image)
                client.images.pull(image)
                container = client.containers.run(
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
                    mem_limit="512m",
                    cpu_quota=50000,
                    command="sleep infinity" if "alpine" in image else None,
                )
                container_ids.append(container.id)
            except docker.errors.APIError as e:
                logger.error("Failed to launch container %s: %s", name, e)
                raise

        return container_ids

    def cleanup(self, scenario_id: str) -> None:
        client = self._get_client()
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

        networks = client.networks.list(
            filters={"label": f"forge.scenario_id={scenario_id}"}
        )
        for network in networks:
            try:
                network.remove()
                logger.info("Removed network %s", network.name)
            except docker.errors.APIError as e:
                logger.warning("Failed to remove network %s: %s", network.name, e)


class StubContainerRuntime(ContainerRuntime):
    def create_network(self, scenario_id: str) -> str:
        return f"stub-network-{scenario_id}"

    def launch_containers(
        self, scenario_id: str, network_id: str, template: dict
    ) -> list[str]:
        return [f"stub-container-{scenario_id}"]

    def cleanup(self, scenario_id: str) -> None:
        return None


class Storage:
    def audit_path(self, scenario_id: str) -> Path:
        raise NotImplementedError


class FileSystemStorage(Storage):
    def __init__(self, root: Path) -> None:
        self._root = root

    def audit_path(self, scenario_id: str) -> Path:
        return self._root / "scenarios" / scenario_id / "results" / "audit.jsonl"


class EventBus:
    async def start(self, app: FastAPI) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def publish(self, subject: str, payload: dict) -> None:
        return None


class MemoryEventBus(EventBus):
    async def publish(self, subject: str, payload: dict) -> None:
        logger.debug("MemoryEventBus publish %s", subject)


class NatsEventBus(EventBus):
    def __init__(self, nats_url: str) -> None:
        self._nats_url = nats_url
        self._task: asyncio.Task | None = None
        self._nc: nats.NATS | None = None
        self._js: Any = None

    async def publish(self, subject: str, payload: dict) -> None:
        if self._js is None:
            return
        await self._js.publish(subject, json.dumps(payload).encode())

    async def start(self, app: FastAPI) -> None:
        self._task = asyncio.create_task(self._subscriber(app))

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        if self._nc:
            await self._nc.close()

    async def _subscriber(self, app: FastAPI) -> None:
        try:
            self._nc = await nats.connect(self._nats_url)
            self._js = self._nc.jetstream()

            try:
                await self._js.add_stream(name="FORGE", subjects=["spawn.*", "scenario.*"])
            except Exception:
                pass

            consumer_config = ConsumerConfig(
                durable_name="orchestrator",
                deliver_policy=DeliverPolicy.ALL,
                ack_wait=30,
            )

            await self._js.subscribe(
                "spawn.request",
                cb=lambda msg: process_spawn_request(app, msg),
                config=consumer_config,
            )
            logger.info("Subscribed to spawn.request")

            while True:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error("NATS subscriber error: %s", e)


class ScoreboardClient:
    async def get_ready(self) -> httpx.Response:
        raise NotImplementedError

    async def post_score(
        self, scenario_id: str, payload: dict, headers: dict
    ) -> httpx.Response:
        raise NotImplementedError


class HttpScoreboardClient(ScoreboardClient):
    def __init__(
        self, base_url: str, transport: httpx.BaseTransport | None = None
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._transport = transport

    async def get_ready(self) -> httpx.Response:
        async with httpx.AsyncClient(
            base_url=self._base_url,
            timeout=_httpx_timeout(),
            transport=self._transport,
        ) as client:
            return await _request_with_retries(
                client, "GET", "/readyz", breaker=_scoreboard_breaker
            )

    async def post_score(
        self, scenario_id: str, payload: dict, headers: dict
    ) -> httpx.Response:
        async with httpx.AsyncClient(
            base_url=self._base_url,
            timeout=_httpx_timeout(),
            transport=self._transport,
        ) as client:
            return await _request_with_retries(
                client,
                "POST",
                f"/internal/scenario/{scenario_id}/score",
                json_body=payload,
                headers=headers,
                breaker=_scoreboard_breaker,
            )


"""Runtime dependencies are stored on app.state."""


def _forge_env() -> str:
    return os.getenv("FORGE_ENV", "dev").lower()


def _enforce_startup_config() -> None:
    env = _forge_env()
    if env not in {"dev", "development"}:
        required = [
            "SAT_HMAC_SECRET",
            "ET_HMAC_SECRET",
            "RECEIPT_HMAC_SECRET",
            "OPERATOR_TOKEN",
        ]
        missing = [name for name in required if not os.getenv(name)]
        if missing:
            raise RuntimeError(f"Missing required secrets: {', '.join(missing)}")


def _policy_dir() -> Path:
    return Path(os.getenv("OPA_POLICY_DIR", "/policies"))


def _compute_policy_hash() -> tuple[str, int]:
    policy_root = _policy_dir()
    files = [
        path
        for path in policy_root.rglob("*.rego")
        if path.is_file()
    ]
    files.sort(key=lambda path: path.relative_to(policy_root).as_posix())
    hasher = hashlib.sha256()
    for path in files:
        rel = path.relative_to(policy_root).as_posix()
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\n")
        hasher.update(path.read_bytes())
        hasher.update(b"\n")
    return hasher.hexdigest(), len(files)


def _enforce_policy_hash() -> None:
    digest, count = _compute_policy_hash()
    logger.info("OPA policy hash=%s files=%s", digest, count)
    expected = os.getenv("OPA_POLICY_HASH")
    if expected:
        if count == 0:
            raise RuntimeError("OPA policy hash enforcement failed: no policies found")
        if digest != expected:
            raise RuntimeError("OPA policy hash enforcement failed: hash mismatch")


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
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
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
    requested_limits: Optional[dict[str, int]] = None
    scenario_id: Optional[str] = None


class ReplayProtector:
    def __init__(self) -> None:
        self._redis_url = os.getenv("REDIS_URL")
        self._redis_client: Any | None = None
        self._cache: OrderedDict[str, int] = OrderedDict()
        self._max_size = int(os.getenv("SAT_REPLAY_CACHE_SIZE", "10000"))
        self._lock = asyncio.Lock()

    async def _get_redis(self) -> Any | None:
        if not self._redis_url:
            return None
        if self._redis_client is None:
            import redis.asyncio as redis

            self._redis_client = redis.from_url(self._redis_url, decode_responses=True)
        return self._redis_client

    def _purge_expired(self, now: int) -> None:
        expired_keys = [key for key, exp in self._cache.items() if exp <= now]
        for key in expired_keys:
            self._cache.pop(key, None)

    async def check_and_store(self, jti: str, exp: int) -> bool:
        now = int(datetime.now(timezone.utc).timestamp())
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


"""Runtime state stored on app.state."""



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
    max_attempts = int(os.getenv("HTTP_MAX_RETRIES", "2")) + 1
    base_delay = float(os.getenv("HTTP_RETRY_BASE_DELAY_SECONDS", "0.2"))
    jitter = float(os.getenv("HTTP_RETRY_JITTER_SECONDS", "0.2"))
    last_exc: Exception | None = None

    for attempt in range(max_attempts):
        try:
            response = await client.request(
                method,
                url,
                json=json_body,
                headers=headers,
            )
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
            delay = base_delay + random.uniform(0, jitter)
            await _sleep(delay)
    raise httpx.RequestError("request failed") from last_exc


_opa_breaker = CircuitBreaker(
    "opa", float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))
)
_scoreboard_breaker = CircuitBreaker(
    "scoreboard", float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))
)
_egress_breaker = CircuitBreaker(
    "egress_gateway", float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))
)




def load_template(track: str, template_dir: Path) -> dict:
    """Load scenario template from filesystem."""
    template_path = template_dir / f"{track}.yaml"
    if not template_path.exists():
        raise HTTPException(status_code=404, detail=f"Template not found: {track}")
    with template_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _get_sat_secret() -> str:
    sat_secret = os.getenv("SAT_HMAC_SECRET")
    if sat_secret:
        return sat_secret
    legacy_secret = os.getenv("SAT_SECRET")
    if legacy_secret:
        _warn_sat_secret_alias()
        return legacy_secret
    raise HTTPException(status_code=500, detail="SAT secret not configured")


def _warn_sat_secret_alias() -> None:
    global _sat_secret_warning_emitted
    if not _sat_secret_warning_emitted:
        logger.warning("SAT_SECRET is deprecated; set SAT_HMAC_SECRET instead")
        _sat_secret_warning_emitted = True


def _parse_bearer_token(value: str) -> Optional[str]:
    if not value:
        return None
    parts = value.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


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


def _get_scoreboard_client(app: FastAPI) -> ScoreboardClient:
    return app.state.scoreboard_client


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
    app: FastAPI,
) -> None:
    token = os.getenv("SCOREBOARD_INTERNAL_TOKEN")
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
    client = _get_scoreboard_client(app)
    response = await client.post_score(scenario_id, payload, headers)
    if response.status_code >= 400:
        raise RuntimeError(
            f"scoreboard error {response.status_code}: {response.text}"
        )


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

    signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
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

    now = int(datetime.now(timezone.utc).timestamp())
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

    stored = await app.state.replay_protector.check_and_store(
        claims.jti, claims.exp
    )
    if not stored:
        raise HTTPException(status_code=401, detail="sat replayed")

    return claims


async def check_opa_policy(
    app: FastAPI, input_payload: dict
) -> tuple[bool, str | None]:
    """Query policy evaluator for decision."""
    return await app.state.policy_evaluator.allow(input_payload)


async def _check_opa_ready(app: FastAPI) -> None:
    await app.state.policy_evaluator.ready()


def _read_only_required() -> bool:
    if os.getenv("READ_ONLY_REQUIRED", "").lower() == "true":
        return True
    forge_env = os.getenv("FORGE_ENV", "dev").lower()
    return forge_env in {"staging", "prod", "production"}


def _check_read_only_fs() -> None:
    if not _read_only_required():
        return
    probe_path = Path("/.forge_read_only_probe")
    try:
        probe_path.write_text("probe", encoding="utf-8")
    except OSError:
        return
    else:
        try:
            probe_path.unlink()
        except OSError:
            pass
        raise HTTPException(status_code=503, detail="filesystem not read-only")


async def _check_egress_gateway() -> None:
    egress_url = os.getenv("EGRESS_GATEWAY_URL")
    if not egress_url:
        return
    expected = os.getenv("EGRESS_DRY_RUN_EXPECTED")
    if expected is None:
        forge_env = os.getenv("FORGE_ENV", "dev").lower()
        expected = "true" if forge_env == "dev" else "false"
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
        raise HTTPException(
            status_code=503, detail="egress gateway invalid response"
        ) from exc
    if str(payload.get("dry_run", "")).lower() != expected.lower():
        raise HTTPException(status_code=503, detail="egress gateway config mismatch")


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _audit_payload(entry: dict[str, Any]) -> bytes:
    payload = dict(entry)
    payload.pop("entry_hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _audit_path(app: FastAPI, scenario_id: str) -> Path:
    return app.state.storage.audit_path(scenario_id)


def append_audit_event(
    app: FastAPI,
    scenario_id: str,
    event_type: str,
    actor: str,
    correlation_id: str,
    details: dict[str, Any],
) -> None:
    audit_path = _audit_path(app, scenario_id)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = "0" * 64
    if audit_path.exists():
        last_line = ""
        with audit_path.open("r", encoding="utf-8") as handle:
            for last_line in handle:
                pass
        if last_line:
            try:
                prev_hash = json.loads(last_line).get("entry_hash", prev_hash)
            except json.JSONDecodeError:
                prev_hash = "0" * 64
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
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


def create_scenario_network(app: FastAPI, scenario_id: str) -> str:
    """Create isolated network for scenario."""
    return app.state.container_runtime.create_network(scenario_id)


def launch_scenario_containers(
    app: FastAPI, scenario_id: str, network_id: str, template: dict
) -> list[str]:
    """Launch containers defined in scenario template."""
    return app.state.container_runtime.launch_containers(
        scenario_id, network_id, template
    )


def cleanup_scenario(app: FastAPI, scenario_id: str) -> None:
    """Remove all resources associated with a scenario."""
    app.state.container_runtime.cleanup(scenario_id)


async def complete_scenario(
    scenario_id: str,
    completion_reason: str,
    app: FastAPI,
    completion_timestamp: datetime | None = None,
) -> ScenarioState:
    scenarios = app.state.scenarios
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail="Scenario not found")
    state = scenarios[scenario_id]
    completed_at = completion_timestamp or datetime.now(timezone.utc)
    state.completed_at = completed_at
    state.completion_reason = completion_reason
    state.updated_at = datetime.now(timezone.utc)

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
            app,
        )
        state.status = ScenarioStatus.COMPLETED
    except Exception as exc:
        state.status = ScenarioStatus.COMPLETED_WITH_ERRORS
        state.error = str(exc)
        logger.error(
            "Scenario %s scoring failed: %s",
            scenario_id,
            exc,
        )
        raise HTTPException(status_code=502, detail=f"scoring failed: {exc}") from exc

    return state


async def process_spawn_request(app: FastAPI, msg: Any) -> None:
    """Process incoming spawn request from NATS."""
    try:
        import json

        data = json.loads(msg.data.decode())
        scenario_id = data.get("scenario_id")
        track = data.get("track")
        request_id = data.get("request_id")
        tier = data.get("tier")
        sat = data.get("sat")

        if not scenario_id or not track or not tier:
            logger.warning("Spawn request missing scenario_id, track, or tier")
            await msg.ack()
            return

        try:
            claims = await enforce_sat(app, sat, scenario_id, track, track, tier)
        except HTTPException as exc:
            logger.warning("Spawn request denied: %s", exc.detail)
            await msg.ack()
            return
        correlation_id = data.get("correlation_id") or request_id or "-"

        logger.info(
            "Processing spawn request: scenario_id=%s track=%s request_id=%s",
            scenario_id,
            track,
            request_id,
        )

        # Load and validate template
        template = load_template(track, app.state.config.template_dir)

        # Check OPA policy
        allowed, reason = await check_opa_policy(
            app, _build_opa_input(template, claims)
        )
        if not allowed:
            logger.warning("Scenario %s denied by policy: %s", scenario_id, reason)
            await msg.ack()
            return

        # Create scenario state
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
        scenarios = app.state.scenarios
        scenarios[scenario_id] = state
        append_audit_event(
            app,
            scenario_id=scenario_id,
            event_type="scenario.create",
            actor=claims.subject,
            correlation_id=correlation_id,
            details={"track": track, "tenant_id": claims.tenant_id},
        )

        runtime = app.state.container_runtime
        event_bus = app.state.event_bus

        # Create network
        network_id = create_scenario_network(app, scenario_id)
        state.network_id = network_id

        # Launch containers
        container_ids = launch_scenario_containers(
            app, scenario_id, network_id, template
        )
        state.containers = container_ids
        state.status = ScenarioStatus.RUNNING
        state.updated_at = datetime.now(timezone.utc)

        logger.info(
            "Scenario %s is now running with %d containers",
            scenario_id,
            len(container_ids),
        )

        # Publish scenario.created event
        if event_bus:
            await event_bus.publish(
                "scenario.created",
                {
                    "scenario_id": scenario_id,
                    "track": track,
                    "network_id": network_id,
                    "containers": container_ids,
                },
            )

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing spawn request: %s", e)
        if msg:
            await msg.nak()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    _enforce_startup_config()
    _enforce_policy_hash()
    if os.getenv("SAT_SECRET") and not os.getenv("SAT_HMAC_SECRET"):
        _warn_sat_secret_alias()
    event_bus = app.state.event_bus
    await event_bus.start(app)
    logger.info("Orchestrator started")
    yield
    await event_bus.stop()
    logger.info("Orchestrator stopped")


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


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_orchestrator"}


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_orchestrator"}


@router.get("/readyz")
async def readyz(request: Request) -> dict:
    _check_read_only_fs()
    await _check_egress_gateway()
    await _check_opa_ready(request.app)
    try:
        client = _get_scoreboard_client(request.app)
        response = await client.get_ready()
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=503, detail=f"scoreboard unavailable: {exc}"
        ) from exc
    if response.status_code >= 400:
        raise HTTPException(
            status_code=503,
            detail=f"scoreboard unhealthy: {response.status_code}",
        )
    return {"status": "ready", "service": "forge_orchestrator"}


@router.post("/v1/scenarios", response_model=CreateScenarioResponse)
async def create_scenario(
    request: CreateScenarioRequest, http_request: Request
) -> CreateScenarioResponse:
    """Create a new scenario (direct API, bypasses NATS)."""
    scenario_id = request.scenario_id
    track = request.template
    token = http_request.headers.get("x-sat")
    if not token:
        token = _parse_bearer_token(http_request.headers.get("authorization", ""))
    claims = await enforce_sat(
        http_request.app, token, scenario_id, track, track, request.tier
    )

    # Check if already exists
    scenarios = http_request.app.state.scenarios
    if scenario_id in scenarios:
        state = scenarios[scenario_id]
        return CreateScenarioResponse(
            scenario_id=scenario_id,
            status=state.status,
            network_id=state.network_id,
        )

    scenarios = app.state.scenarios

    # Create scenario state
    state = ScenarioState(
        scenario_id=scenario_id,
        request_id=request.request_id,
        track=track,
        subject=claims.subject,
        tenant_id=claims.tenant_id,
        tier=_normalize_plan(claims.tier),
        retention_days=claims.retention_days,
        status=ScenarioStatus.CREATING,
    )
    scenarios[scenario_id] = state
    append_audit_event(
        http_request.app,
        scenario_id=scenario_id,
        event_type="scenario.create",
        actor=claims.subject,
        correlation_id=request_id_ctx.get(),
        details={"track": track, "tenant_id": claims.tenant_id},
    )

    # Load and validate template
    template = load_template(track, http_request.app.state.config.template_dir)

    # Check OPA policy
    allowed, reason = await check_opa_policy(
        http_request.app, _build_opa_input(template, claims)
    )
    if not allowed:
        state.status = ScenarioStatus.FAILED
        state.error = reason
        raise HTTPException(status_code=403, detail=reason)

    # Create network
    try:
        network_id = create_scenario_network(http_request.app, scenario_id)
        state.network_id = network_id
    except Exception as e:
        state.status = ScenarioStatus.FAILED
        state.error = str(e)
        raise HTTPException(status_code=500, detail=f"Network creation failed: {e}")

    # Launch containers
    try:
        container_ids = launch_scenario_containers(
            http_request.app, scenario_id, network_id, template
        )
        state.containers = container_ids
        state.status = ScenarioStatus.RUNNING
        state.updated_at = datetime.now(timezone.utc)
    except Exception as e:
        cleanup_scenario(http_request.app, scenario_id)
        state.status = ScenarioStatus.FAILED
        state.error = str(e)
        raise HTTPException(status_code=500, detail=f"Container launch failed: {e}")

    return CreateScenarioResponse(
        scenario_id=scenario_id,
        status=state.status,
        network_id=network_id,
    )


@router.get("/v1/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str, request: Request) -> ScenarioState:
    """Get scenario status."""
    scenarios = request.app.state.scenarios
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenarios[scenario_id]


@router.delete("/v1/scenarios/{scenario_id}")
async def delete_scenario(scenario_id: str, request: Request) -> dict:
    """Delete a scenario and cleanup resources."""
    scenarios = request.app.state.scenarios
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail="Scenario not found")

    cleanup_scenario(request.app, scenario_id)
    del scenarios[scenario_id]

    return {"status": "deleted", "scenario_id": scenario_id}


@router.get("/v1/scenarios")
async def list_scenarios(request: Request) -> list[ScenarioState]:
    """List all scenarios."""
    scenarios = request.app.state.scenarios
    return list(scenarios.values())


@router.post("/internal/scenario/{scenario_id}/complete")
async def complete_scenario_endpoint(
    scenario_id: str,
    payload: ScenarioCompletionRequest,
    request: Request,
) -> ScenarioState:
    _require_internal_auth(request)
    _require_operator_auth(request)
    return await complete_scenario(
        scenario_id,
        payload.completion_reason,
        request.app,
        payload.completion_timestamp,
    )


def _build_policy_evaluator(config: OrchestratorConfig) -> PolicyEvaluator:
    if config.policy_backend == "allow_all":
        return AllowAllPolicyEvaluator()
    return OpaPolicyEvaluator(config.opa_url)


def _build_container_runtime(config: OrchestratorConfig) -> ContainerRuntime:
    if config.container_backend == "stub":
        return StubContainerRuntime()
    return DockerContainerRuntime()


def _build_storage(config: OrchestratorConfig) -> Storage:
    return FileSystemStorage(config.storage_root)


def _build_event_bus(config: OrchestratorConfig) -> EventBus:
    if config.event_bus_backend == "memory":
        return MemoryEventBus()
    return NatsEventBus(config.nats_url)


def _build_scoreboard_client(config: OrchestratorConfig) -> ScoreboardClient:
    if config.scoreboard_app is not None:
        transport = httpx.ASGITransport(app=config.scoreboard_app)
        return HttpScoreboardClient("http://scoreboard", transport=transport)
    return HttpScoreboardClient(config.scoreboard_url)


def create_app(config: OrchestratorConfig) -> FastAPI:
    policy_evaluator = _build_policy_evaluator(config)
    container_runtime = _build_container_runtime(config)
    storage = _build_storage(config)
    event_bus = _build_event_bus(config)
    scoreboard_client = _build_scoreboard_client(config)

    app = FastAPI(title="FrostGate Forge Orchestrator", lifespan=lifespan)
    app.state.config = config
    app.state.policy_evaluator = policy_evaluator
    app.state.container_runtime = container_runtime
    app.state.storage = storage
    app.state.event_bus = event_bus
    app.state.scoreboard_client = scoreboard_client
    app.state.scenarios = {}
    app.state.replay_protector = ReplayProtector()

    app.middleware("http")(add_request_id)
    app.include_router(router)
    return app


app = create_app(OrchestratorConfig.from_env())
