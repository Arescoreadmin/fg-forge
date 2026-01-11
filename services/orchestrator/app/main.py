"""FrostGate Forge Orchestrator Service.

Central coordinator for scenario lifecycle management. Validates templates,
enforces OPA policies, creates isolated networks, and manages container lifecycles.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hmac
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


class ScenarioStatus(str, Enum):
    PENDING = "pending"
    CREATING = "creating"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ScenarioState(BaseModel):
    scenario_id: str
    request_id: str
    track: str
    status: ScenarioStatus = ScenarioStatus.PENDING
    network_id: str | None = None
    containers: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None


class CreateScenarioRequest(BaseModel):
    scenario_id: str
    template: str
    request_id: str


class CreateScenarioResponse(BaseModel):
    scenario_id: str
    status: ScenarioStatus
    network_id: str | None = None


class SatClaims(BaseModel):
    jti: str
    exp: int
    iat: int
    track: str
    template_id: str
    subject: str
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
) -> SatClaims:
    if not token:
        raise HTTPException(status_code=401, detail="sat required")

    claims = verify_sat(token)
    if scenario_id and claims.scenario_id and claims.scenario_id != scenario_id:
        raise HTTPException(status_code=403, detail="sat scenario mismatch")
    if track and claims.track != track:
        raise HTTPException(status_code=403, detail="sat track mismatch")
    if template_id and claims.template_id != template_id:
        raise HTTPException(status_code=403, detail="sat template mismatch")

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


async def process_spawn_request(msg: Any) -> None:
    """Process incoming spawn request from NATS."""
    try:
        import json

        data = json.loads(msg.data.decode())
        scenario_id = data.get("scenario_id")
        track = data.get("track")
        request_id = data.get("request_id")
        sat = data.get("sat")

        if not scenario_id or not track:
            logger.warning("Spawn request missing scenario_id or track")
            await msg.ack()
            return

        try:
            await enforce_sat(sat, scenario_id, track, track)
        except HTTPException as exc:
            logger.warning("Spawn request denied: %s", exc.detail)
            await msg.ack()
            return

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
            status=ScenarioStatus.CREATING,
        )
        scenarios[scenario_id] = state

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
def readyz() -> dict:
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
    await enforce_sat(token, scenario_id, track, track)

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
        status=ScenarioStatus.CREATING,
    )
    scenarios[scenario_id] = state

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
