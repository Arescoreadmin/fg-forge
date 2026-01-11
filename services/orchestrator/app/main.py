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
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import docker
import httpx
import nats
import yaml
from fastapi import FastAPI, HTTPException, Request
from nats.js.api import ConsumerConfig, DeliverPolicy
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
logger = logging.getLogger("forge_orchestrator")
_sat_secret_warning_emitted = False

# Configuration
TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", "/templates"))
OPA_URL = os.getenv("OPA_URL", "http://forge_opa:8181")
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
NETWORK_PREFIX = "forge_scn_"
SCOREBOARD_URL = os.getenv("SCOREBOARD_URL", "http://forge_scoreboard:8080")
STORAGE_ROOT = Path(os.getenv("STORAGE_ROOT", "storage"))


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


# In-memory state store (production would use Redis/NATS KV)
scenarios: dict[str, ScenarioState] = {}

replay_protector = ReplayProtector()

# Docker client
docker_client: docker.DockerClient | None = None

# NATS client
nc: nats.NATS | None = None
js: Any = None


def get_docker_client() -> docker.DockerClient:
    global docker_client
    if docker_client is None:
        docker_client = docker.from_env()
    return docker_client


def load_template(track: str) -> dict:
    """Load scenario template from filesystem."""
    template_path = TEMPLATE_DIR / f"{track}.yaml"
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


def _scoreboard_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=SCOREBOARD_URL, timeout=5.0)


async def _trigger_scoreboard(
    scenario_id: str,
    track: str,
    completion_reason: str,
    completed_at: datetime,
    subject: str | None,
    tenant_id: str | None,
    correlation_id: str | None,
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
    }
    headers = {"x-internal-token": token}
    if correlation_id:
        headers["x-request-id"] = correlation_id
    async with _scoreboard_client() as client:
        response = await client.post(
            f"/internal/scenario/{scenario_id}/score", json=payload, headers=headers
        )
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

    stored = await replay_protector.check_and_store(claims.jti, claims.exp)
    if not stored:
        raise HTTPException(status_code=401, detail="sat replayed")

    return claims


async def check_opa_policy(template: dict) -> tuple[bool, str | None]:
    """Query OPA for policy decision."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.post(
                f"{OPA_URL}/v1/data/frostgate/forge/training/allow",
                json={"input": template},
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


async def _check_opa_ready() -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(f"{OPA_URL}/health")
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=503, detail=f"opa unavailable: {exc}"
            ) from exc
    if response.status_code >= 400:
        raise HTTPException(
            status_code=503, detail=f"opa unhealthy: {response.status_code}"
        )


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _audit_payload(entry: dict[str, Any]) -> bytes:
    payload = dict(entry)
    payload.pop("entry_hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _audit_path(scenario_id: str) -> Path:
    return STORAGE_ROOT / "scenarios" / scenario_id / "results" / "audit.jsonl"


def append_audit_event(
    scenario_id: str,
    event_type: str,
    actor: str,
    correlation_id: str,
    details: dict[str, Any],
) -> None:
    audit_path = _audit_path(scenario_id)
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


def create_scenario_network(scenario_id: str) -> str:
    """Create isolated Docker network for scenario."""
    client = get_docker_client()
    network_name = f"{NETWORK_PREFIX}{scenario_id}"

    network = client.networks.create(
        name=network_name,
        driver="bridge",
        internal=True,  # No external access by default
        labels={
            "forge.scenario_id": scenario_id,
            "forge.created_at": datetime.now(timezone.utc).isoformat(),
            "forge.managed": "true",
        },
    )
    logger.info("Created network %s for scenario %s", network_name, scenario_id)
    return network.id


def launch_scenario_containers(
    scenario_id: str, network_id: str, template: dict
) -> list[str]:
    """Launch containers defined in scenario template."""
    client = get_docker_client()
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
                cpu_quota=50000,  # 50% of one CPU
                # Keep container running
                command="sleep infinity" if "alpine" in image else None,
            )
            container_ids.append(container.id)
            logger.info(
                "Launched container %s (%s) for scenario %s",
                container_name,
                image,
                scenario_id,
            )
        except docker.errors.ImageNotFound:
            logger.warning("Image %s not found, pulling...", image)
            client.images.pull(image)
            # Retry after pull
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


def cleanup_scenario(scenario_id: str) -> None:
    """Remove all resources associated with a scenario."""
    client = get_docker_client()

    # Stop and remove containers
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

    # Remove network
    networks = client.networks.list(filters={"label": f"forge.scenario_id={scenario_id}"})
    for network in networks:
        try:
            network.remove()
            logger.info("Removed network %s", network.name)
        except docker.errors.APIError as e:
            logger.warning("Failed to remove network %s: %s", network.name, e)


async def complete_scenario(
    scenario_id: str, completion_reason: str, completion_timestamp: datetime | None = None
) -> ScenarioState:
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
            request_id_ctx.get(),
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


async def process_spawn_request(msg: Any) -> None:
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
            claims = await enforce_sat(sat, scenario_id, track, track, tier)
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
        template = load_template(track)

        # Check OPA policy
        allowed, reason = await check_opa_policy(template)
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
            tier=claims.tier,
            status=ScenarioStatus.CREATING,
        )
        scenarios[scenario_id] = state
        append_audit_event(
            scenario_id=scenario_id,
            event_type="scenario.create",
            actor=claims.subject,
            correlation_id=correlation_id,
            details={"track": track, "tenant_id": claims.tenant_id},
        )

        # Create network
        network_id = create_scenario_network(scenario_id)
        state.network_id = network_id

        # Launch containers
        container_ids = launch_scenario_containers(scenario_id, network_id, template)
        state.containers = container_ids
        state.status = ScenarioStatus.RUNNING
        state.updated_at = datetime.now(timezone.utc)

        logger.info(
            "Scenario %s is now running with %d containers",
            scenario_id,
            len(container_ids),
        )

        # Publish scenario.created event
        if js:
            await js.publish(
                "scenario.created",
                json.dumps(
                    {
                        "scenario_id": scenario_id,
                        "track": track,
                        "network_id": network_id,
                        "containers": container_ids,
                    }
                ).encode(),
            )

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing spawn request: %s", e)
        if msg:
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS spawn requests."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        # Create stream if not exists
        try:
            await js.add_stream(name="FORGE", subjects=["spawn.*", "scenario.*"])
        except Exception:
            pass  # Stream may already exist

        # Subscribe to spawn requests
        consumer_config = ConsumerConfig(
            durable_name="orchestrator",
            deliver_policy=DeliverPolicy.ALL,
            ack_wait=30,
        )

        sub = await js.subscribe(
            "spawn.request",
            cb=process_spawn_request,
            config=consumer_config,
        )
        logger.info("Subscribed to spawn.request")

        # Keep running
        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logger.error("NATS subscriber error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    if os.getenv("SAT_SECRET") and not os.getenv("SAT_HMAC_SECRET"):
        _warn_sat_secret_alias()
    # Start NATS subscriber in background
    task = asyncio.create_task(nats_subscriber())
    logger.info("Orchestrator started")
    yield
    # Cleanup
    task.cancel()
    if nc:
        await nc.close()
    logger.info("Orchestrator stopped")


app = FastAPI(title="FrostGate Forge Orchestrator", lifespan=lifespan)


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


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_orchestrator"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_orchestrator"}


@app.get("/readyz")
async def readyz() -> dict:
    await _check_opa_ready()
    try:
        async with _scoreboard_client() as client:
            response = await client.get("/readyz")
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


@app.post("/v1/scenarios", response_model=CreateScenarioResponse)
async def create_scenario(
    request: CreateScenarioRequest, http_request: Request
) -> CreateScenarioResponse:
    """Create a new scenario (direct API, bypasses NATS)."""
    scenario_id = request.scenario_id
    track = request.template
    token = http_request.headers.get("x-sat")
    if not token:
        token = _parse_bearer_token(http_request.headers.get("authorization", ""))
    claims = await enforce_sat(token, scenario_id, track, track, request.tier)

    # Check if already exists
    if scenario_id in scenarios:
        state = scenarios[scenario_id]
        return CreateScenarioResponse(
            scenario_id=scenario_id,
            status=state.status,
            network_id=state.network_id,
        )

    # Create scenario state
    state = ScenarioState(
        scenario_id=scenario_id,
        request_id=request.request_id,
        track=track,
        subject=claims.subject,
        tenant_id=claims.tenant_id,
        tier=claims.tier,
        status=ScenarioStatus.CREATING,
    )
    scenarios[scenario_id] = state
    append_audit_event(
        scenario_id=scenario_id,
        event_type="scenario.create",
        actor=claims.subject,
        correlation_id=request_id_ctx.get(),
        details={"track": track, "tenant_id": claims.tenant_id},
    )

    # Load and validate template
    template = load_template(track)

    # Check OPA policy
    allowed, reason = await check_opa_policy(template)
    if not allowed:
        state.status = ScenarioStatus.FAILED
        state.error = reason
        raise HTTPException(status_code=403, detail=reason)

    # Create network
    try:
        network_id = create_scenario_network(scenario_id)
        state.network_id = network_id
    except Exception as e:
        state.status = ScenarioStatus.FAILED
        state.error = str(e)
        raise HTTPException(status_code=500, detail=f"Network creation failed: {e}")

    # Launch containers
    try:
        container_ids = launch_scenario_containers(scenario_id, network_id, template)
        state.containers = container_ids
        state.status = ScenarioStatus.RUNNING
        state.updated_at = datetime.now(timezone.utc)
    except Exception as e:
        cleanup_scenario(scenario_id)
        state.status = ScenarioStatus.FAILED
        state.error = str(e)
        raise HTTPException(status_code=500, detail=f"Container launch failed: {e}")

    return CreateScenarioResponse(
        scenario_id=scenario_id,
        status=state.status,
        network_id=network_id,
    )


@app.get("/v1/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str) -> ScenarioState:
    """Get scenario status."""
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenarios[scenario_id]


@app.delete("/v1/scenarios/{scenario_id}")
async def delete_scenario(scenario_id: str) -> dict:
    """Delete a scenario and cleanup resources."""
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail="Scenario not found")

    cleanup_scenario(scenario_id)
    del scenarios[scenario_id]

    return {"status": "deleted", "scenario_id": scenario_id}


@app.get("/v1/scenarios")
async def list_scenarios() -> list[ScenarioState]:
    """List all scenarios."""
    return list(scenarios.values())


@app.post("/internal/scenario/{scenario_id}/complete")
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
        payload.completion_timestamp,
    )
