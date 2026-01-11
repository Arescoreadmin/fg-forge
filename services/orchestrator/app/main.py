"""FrostGate Forge Orchestrator Service.

Central coordinator for scenario lifecycle management. Validates templates,
enforces OPA policies, creates isolated networks, and manages container lifecycles.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import docker
import httpx
import nats
import yaml
from fastapi import FastAPI, HTTPException
from nats.js.api import ConsumerConfig, DeliverPolicy
from pydantic import BaseModel, Field

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("forge_orchestrator")

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


# In-memory state store (production would use Redis/NATS KV)
scenarios: dict[str, ScenarioState] = {}

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

        logger.info(
            "Processing spawn request: scenario_id=%s track=%s request_id=%s",
            scenario_id,
            track,
            request_id,
        )

        # Create scenario state
        state = ScenarioState(
            scenario_id=scenario_id,
            request_id=request_id,
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
            logger.warning("Scenario %s denied by policy: %s", scenario_id, reason)
            await msg.ack()
            return

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


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_orchestrator"}


@app.post("/v1/scenarios", response_model=CreateScenarioResponse)
async def create_scenario(request: CreateScenarioRequest) -> CreateScenarioResponse:
    """Create a new scenario (direct API, bypasses NATS)."""
    scenario_id = request.scenario_id
    track = request.template

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
