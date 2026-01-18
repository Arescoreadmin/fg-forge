"""FrostGate Forge Egress Gateway Service.

Manages network egress policies using nftables. Enforces deny-all by default
with optional allowlist profiles per scenario network.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
import contextvars
from datetime import UTC, datetime
from enum import Enum
import json
import logging
import os
import subprocess
from typing import Any
import uuid

from fastapi import FastAPI, HTTPException, Request
import nats
from nats.js.api import ConsumerConfig, DeliverPolicy
from pydantic import BaseModel, Field

request_id_ctx = contextvars.ContextVar("request_id", default="-")


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
logger = logging.getLogger("forge_egress_gateway")

# Configuration
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
NFT_BINARY = os.getenv("NFT_BINARY", "/usr/sbin/nft")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"


class AllowlistProfile(str, Enum):
    NONE = "none"
    TRAINING_UPDATES = "training-updates"
    EXTERNAL_API = "external-api"
    CUSTOM = "custom"


class EgressPolicy(BaseModel):
    scenario_id: str
    network_id: str
    profile: AllowlistProfile = AllowlistProfile.NONE
    custom_rules: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EgressLogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scenario_id: str | None = None
    network_id: str | None = None
    action: str  # "allow" or "deny"
    src_ip: str
    dst_ip: str
    dst_port: int | None = None
    protocol: str = "tcp"
    reason: str | None = None


class PolicyStats(BaseModel):
    total_policies: int = 0
    active_policies: int = 0
    denied_requests: int = 0
    allowed_requests: int = 0


# In-memory stores
policies: dict[str, EgressPolicy] = {}
egress_logs: list[EgressLogEntry] = []
stats = PolicyStats()

# NATS client
nc: nats.NATS | None = None
js: Any = None


def run_nft_command(args: list[str]) -> tuple[bool, str]:
    """Execute nftables command."""
    if DRY_RUN:
        logger.info("[DRY_RUN] nft %s", " ".join(args))
        return True, "dry run"

    try:
        result = subprocess.run(
            [NFT_BINARY, *args],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.error("nft command failed: %s", result.stderr)
            return False, result.stderr
        return True, result.stdout
    except subprocess.TimeoutExpired:
        logger.error("nft command timed out")
        return False, "timeout"
    except FileNotFoundError:
        logger.warning("nft binary not found, running in simulation mode")
        return True, "simulation"
    except Exception as e:
        logger.error("nft command error: %s", e)
        return False, str(e)


def init_base_ruleset() -> bool:
    """Initialize base nftables ruleset."""
    commands = [
        ["flush", "ruleset"],
        ["add", "table", "inet", "forge_egress"],
        [
            "add",
            "chain",
            "inet",
            "forge_egress",
            "output",
            "{ type filter hook output priority 0 ; policy drop ; }",
        ],
        # Allow established connections
        [
            "add",
            "rule",
            "inet",
            "forge_egress",
            "output",
            "ct",
            "state",
            "established,related",
            "accept",
        ],
        # Allow loopback
        ["add", "rule", "inet", "forge_egress", "output", "oif", "lo", "accept"],
        # Allow internal networks
        [
            "add",
            "rule",
            "inet",
            "forge_egress",
            "output",
            "ip",
            "daddr",
            "10.0.0.0/8",
            "accept",
        ],
        [
            "add",
            "rule",
            "inet",
            "forge_egress",
            "output",
            "ip",
            "daddr",
            "172.16.0.0/12",
            "accept",
        ],
        [
            "add",
            "rule",
            "inet",
            "forge_egress",
            "output",
            "ip",
            "daddr",
            "192.168.0.0/16",
            "accept",
        ],
    ]

    for cmd in commands:
        success, _ = run_nft_command(cmd)
        if not success:
            return False
    return True


def apply_profile_rules(profile: AllowlistProfile) -> list[list[str]]:
    """Get nftables rules for an allowlist profile."""
    if profile == AllowlistProfile.TRAINING_UPDATES:
        return [
            [
                "add",
                "rule",
                "inet",
                "forge_egress",
                "output",
                "tcp",
                "dport",
                "443",
                "accept",
            ],
            [
                "add",
                "rule",
                "inet",
                "forge_egress",
                "output",
                "tcp",
                "dport",
                "80",
                "accept",
            ],
        ]
    elif profile == AllowlistProfile.EXTERNAL_API:
        return [
            [
                "add",
                "rule",
                "inet",
                "forge_egress",
                "output",
                "tcp",
                "dport",
                "443",
                "accept",
            ],
        ]
    return []


def apply_policy(policy: EgressPolicy) -> bool:
    """Apply egress policy for a scenario."""
    logger.info(
        "Applying egress policy for scenario %s (profile: %s)",
        policy.scenario_id,
        policy.profile,
    )

    # Apply profile rules
    for cmd in apply_profile_rules(policy.profile):
        success, _ = run_nft_command(cmd)
        if not success:
            return False

    # Apply custom host allowlist
    for host in policy.allowed_hosts:
        cmd = [
            "add",
            "rule",
            "inet",
            "forge_egress",
            "output",
            "ip",
            "daddr",
            host,
            "accept",
        ]
        run_nft_command(cmd)

    # Apply custom port allowlist
    for port in policy.allowed_ports:
        cmd = [
            "add",
            "rule",
            "inet",
            "forge_egress",
            "output",
            "tcp",
            "dport",
            str(port),
            "accept",
        ]
        run_nft_command(cmd)

    return True


def remove_policy(policy: EgressPolicy) -> bool:
    """Remove egress policy for a scenario (reinitialize ruleset)."""
    logger.info("Removing egress policy for scenario %s", policy.scenario_id)
    # For simplicity, we reinitialize the ruleset
    # In production, you'd want to track and remove specific rules
    return init_base_ruleset()


async def log_egress_event(
    action: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int | None = None,
    scenario_id: str | None = None,
    reason: str | None = None,
) -> None:
    """Log an egress event and publish to NATS."""
    entry = EgressLogEntry(
        scenario_id=scenario_id,
        action=action,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        reason=reason,
    )
    egress_logs.append(entry)

    if action == "deny":
        stats.denied_requests += 1
    else:
        stats.allowed_requests += 1

    # Publish to NATS audit stream
    if js:
        try:
            await js.publish(
                "audit.egress",
                json.dumps(
                    {
                        "timestamp": entry.timestamp.isoformat(),
                        "scenario_id": scenario_id,
                        "action": action,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "reason": reason,
                    }
                ).encode(),
            )
        except Exception as e:
            logger.warning("Failed to publish egress log: %s", e)


async def process_scenario_created(msg: Any) -> None:
    """Process scenario.created events to set up egress policies."""
    try:
        data = json.loads(msg.data.decode())
        scenario_id = data.get("scenario_id")
        network_id = data.get("network_id")
        track = data.get("track")

        logger.info(
            "Setting up egress policy for scenario %s (track: %s)",
            scenario_id,
            track,
        )

        # Determine profile based on track
        profile = AllowlistProfile.NONE
        if track in ["netplus", "ccna"]:
            profile = AllowlistProfile.NONE  # Strict for network training
        elif track == "cissp":
            profile = AllowlistProfile.TRAINING_UPDATES  # May need external resources

        # Create and apply policy
        policy = EgressPolicy(
            scenario_id=scenario_id,
            network_id=network_id,
            profile=profile,
        )
        policies[scenario_id] = policy
        stats.total_policies += 1
        stats.active_policies += 1

        apply_policy(policy)

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing scenario.created: %s", e)
        if msg:
            await msg.nak()


async def process_scenario_completed(msg: Any) -> None:
    """Process scenario.completed events to tear down egress policies."""
    try:
        data = json.loads(msg.data.decode())
        scenario_id = data.get("scenario_id")

        if scenario_id in policies:
            policy = policies[scenario_id]
            policy.enabled = False
            stats.active_policies -= 1
            logger.info("Disabled egress policy for completed scenario %s", scenario_id)

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing scenario.completed: %s", e)
        if msg:
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS events for egress policy management."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        # Ensure audit stream exists
        with suppress(Exception):
            await js.add_stream(name="AUDIT", subjects=["audit.*"])

        # Subscribe to scenario events
        created_config = ConsumerConfig(
            durable_name="egress_gateway_created",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=10,
        )
        await js.subscribe(
            "scenario.created",
            cb=process_scenario_created,
            config=created_config,
        )

        completed_config = ConsumerConfig(
            durable_name="egress_gateway_completed",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=10,
        )
        await js.subscribe(
            "scenario.completed",
            cb=process_scenario_completed,
            config=completed_config,
        )

        logger.info("Subscribed to scenario events for egress policy management")

        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logger.error("NATS subscriber error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Initialize base ruleset
    if not DRY_RUN:
        init_base_ruleset()

    task = asyncio.create_task(nats_subscriber())
    logger.info("Egress gateway started (dry_run=%s)", DRY_RUN)
    yield
    task.cancel()
    if nc:
        await nc.close()
    logger.info("Egress gateway stopped")


app = FastAPI(title="FrostGate Forge Egress Gateway", lifespan=lifespan)


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
    return {"status": "ok", "service": "forge_egress_gateway", "dry_run": DRY_RUN}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_egress_gateway", "dry_run": DRY_RUN}


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "service": "forge_egress_gateway", "dry_run": DRY_RUN}


@app.get("/v1/policies")
async def list_policies() -> list[EgressPolicy]:
    """List all egress policies."""
    return list(policies.values())


@app.get("/v1/policies/{scenario_id}")
async def get_policy(scenario_id: str) -> EgressPolicy:
    """Get egress policy for a scenario."""
    if scenario_id not in policies:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policies[scenario_id]


@app.post("/v1/policies")
async def create_policy(policy: EgressPolicy) -> EgressPolicy:
    """Create or update an egress policy."""
    policies[policy.scenario_id] = policy
    stats.total_policies += 1
    stats.active_policies += 1

    if policy.enabled:
        apply_policy(policy)

    logger.info("Created egress policy for scenario %s", policy.scenario_id)
    return policy


@app.delete("/v1/policies/{scenario_id}")
async def delete_policy(scenario_id: str) -> dict:
    """Delete an egress policy."""
    if scenario_id not in policies:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = policies.pop(scenario_id)
    stats.active_policies -= 1
    remove_policy(policy)

    return {"status": "deleted", "scenario_id": scenario_id}


@app.post("/v1/policies/{scenario_id}/enable")
async def enable_policy(scenario_id: str) -> EgressPolicy:
    """Enable an egress policy."""
    if scenario_id not in policies:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = policies[scenario_id]
    if not policy.enabled:
        policy.enabled = True
        stats.active_policies += 1
        apply_policy(policy)

    return policy


@app.post("/v1/policies/{scenario_id}/disable")
async def disable_policy(scenario_id: str) -> EgressPolicy:
    """Disable an egress policy."""
    if scenario_id not in policies:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = policies[scenario_id]
    if policy.enabled:
        policy.enabled = False
        stats.active_policies -= 1

    return policy


@app.get("/v1/logs")
async def get_logs(
    scenario_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
) -> list[EgressLogEntry]:
    """Get egress logs."""
    result = egress_logs
    if scenario_id:
        result = [e for e in result if e.scenario_id == scenario_id]
    if action:
        result = [e for e in result if e.action == action]
    return result[-limit:]


@app.get("/v1/stats")
async def get_stats() -> PolicyStats:
    """Get egress gateway statistics."""
    return stats


@app.get("/v1/ruleset")
async def get_ruleset() -> dict:
    """Get current nftables ruleset."""
    success, output = run_nft_command(["list", "ruleset"])
    return {"success": success, "ruleset": output}


@app.get("/v1/profiles")
async def list_profiles() -> list[dict]:
    """List available allowlist profiles."""
    return [
        {
            "name": AllowlistProfile.NONE.value,
            "description": "Strict deny-all (internal networks only)",
        },
        {
            "name": AllowlistProfile.TRAINING_UPDATES.value,
            "description": "Allow HTTP/HTTPS for package updates",
        },
        {
            "name": AllowlistProfile.EXTERNAL_API.value,
            "description": "Allow HTTPS for external API access",
        },
        {
            "name": AllowlistProfile.CUSTOM.value,
            "description": "Custom rules with explicit host/port allowlist",
        },
    ]
