"""FrostGate Forge Metrics Tuner Service.

Quota and fairness enforcement layer. Tracks per-tenant usage against quotas,
emits alerts for fairness and abuse detection, and publishes enforcement
decisions to NATS.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import nats
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
logger = logging.getLogger("forge_metrics_tuner")

# Configuration
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
DEFAULT_QUOTA_SCENARIOS = int(os.getenv("DEFAULT_QUOTA_SCENARIOS", "10"))
DEFAULT_QUOTA_WINDOW_HOURS = int(os.getenv("DEFAULT_QUOTA_WINDOW_HOURS", "24"))
ABUSE_THRESHOLD_RATE = float(os.getenv("ABUSE_THRESHOLD_RATE", "5.0"))  # per minute


class QuotaStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"
    EXCEEDED = "exceeded"
    BLOCKED = "blocked"


class TenantQuota(BaseModel):
    tenant_id: str
    max_scenarios: int = DEFAULT_QUOTA_SCENARIOS
    window_hours: int = DEFAULT_QUOTA_WINDOW_HOURS
    max_concurrent: int = 3
    tracks_allowed: list[str] = Field(default_factory=lambda: ["netplus", "ccna", "cissp"])


class TenantUsage(BaseModel):
    tenant_id: str
    scenarios_started: int = 0
    scenarios_completed: int = 0
    scenarios_failed: int = 0
    active_scenarios: list[str] = Field(default_factory=list)
    last_spawn_time: datetime | None = None
    spawn_timestamps: list[datetime] = Field(default_factory=list)
    window_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class QuotaCheckResult(BaseModel):
    allowed: bool
    status: QuotaStatus
    reason: str | None = None
    remaining: int = 0
    reset_at: datetime | None = None


class FairnessAlert(BaseModel):
    tenant_id: str
    alert_type: str
    severity: str
    message: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metrics: dict[str, Any] = Field(default_factory=dict)


# In-memory stores (production would use Redis)
tenant_quotas: dict[str, TenantQuota] = {}
tenant_usage: dict[str, TenantUsage] = {}
alerts: list[FairnessAlert] = []
blocked_tenants: set[str] = set()

# NATS client
nc: nats.NATS | None = None
js: Any = None


def get_or_create_quota(tenant_id: str) -> TenantQuota:
    """Get or create default quota for a tenant."""
    if tenant_id not in tenant_quotas:
        tenant_quotas[tenant_id] = TenantQuota(tenant_id=tenant_id)
    return tenant_quotas[tenant_id]


def get_or_create_usage(tenant_id: str) -> TenantUsage:
    """Get or create usage tracker for a tenant."""
    if tenant_id not in tenant_usage:
        tenant_usage[tenant_id] = TenantUsage(tenant_id=tenant_id)
    return tenant_usage[tenant_id]


def cleanup_expired_timestamps(usage: TenantUsage, quota: TenantQuota) -> None:
    """Remove timestamps outside the quota window."""
    window_start = datetime.now(timezone.utc) - timedelta(hours=quota.window_hours)
    usage.spawn_timestamps = [
        ts for ts in usage.spawn_timestamps if ts >= window_start
    ]
    usage.window_start = window_start


def check_rate_abuse(usage: TenantUsage) -> tuple[bool, float]:
    """Check if tenant is spawning scenarios too rapidly."""
    now = datetime.now(timezone.utc)
    one_minute_ago = now - timedelta(minutes=1)
    recent_spawns = [
        ts for ts in usage.spawn_timestamps if ts >= one_minute_ago
    ]
    rate = len(recent_spawns)
    return rate >= ABUSE_THRESHOLD_RATE, rate


def check_quota(tenant_id: str, track: str | None = None) -> QuotaCheckResult:
    """Check if tenant can spawn a new scenario."""
    # Check if blocked
    if tenant_id in blocked_tenants:
        return QuotaCheckResult(
            allowed=False,
            status=QuotaStatus.BLOCKED,
            reason="Tenant is blocked due to abuse",
        )

    quota = get_or_create_quota(tenant_id)
    usage = get_or_create_usage(tenant_id)

    # Clean up expired timestamps
    cleanup_expired_timestamps(usage, quota)

    # Check track allowlist
    if track and track not in quota.tracks_allowed:
        return QuotaCheckResult(
            allowed=False,
            status=QuotaStatus.EXCEEDED,
            reason=f"Track '{track}' not allowed for tenant",
        )

    # Check concurrent limit
    if len(usage.active_scenarios) >= quota.max_concurrent:
        return QuotaCheckResult(
            allowed=False,
            status=QuotaStatus.EXCEEDED,
            reason=f"Concurrent scenario limit ({quota.max_concurrent}) reached",
            remaining=0,
        )

    # Check quota window
    scenarios_in_window = len(usage.spawn_timestamps)
    remaining = quota.max_scenarios - scenarios_in_window

    if remaining <= 0:
        reset_at = usage.window_start + timedelta(hours=quota.window_hours)
        return QuotaCheckResult(
            allowed=False,
            status=QuotaStatus.EXCEEDED,
            reason=f"Quota limit ({quota.max_scenarios}) exceeded for window",
            remaining=0,
            reset_at=reset_at,
        )

    # Check for warning threshold (80% used)
    warning_threshold = int(quota.max_scenarios * 0.8)
    status = QuotaStatus.OK
    if scenarios_in_window >= warning_threshold:
        status = QuotaStatus.WARNING

    return QuotaCheckResult(
        allowed=True,
        status=status,
        remaining=remaining,
        reset_at=usage.window_start + timedelta(hours=quota.window_hours),
    )


def record_spawn(tenant_id: str, scenario_id: str) -> None:
    """Record a scenario spawn for a tenant."""
    usage = get_or_create_usage(tenant_id)
    now = datetime.now(timezone.utc)

    usage.scenarios_started += 1
    usage.spawn_timestamps.append(now)
    usage.last_spawn_time = now
    usage.active_scenarios.append(scenario_id)

    # Check for rate abuse
    is_abuse, rate = check_rate_abuse(usage)
    if is_abuse:
        alert = FairnessAlert(
            tenant_id=tenant_id,
            alert_type="rate_abuse",
            severity="warning",
            message=f"High spawn rate detected: {rate}/min",
            metrics={"rate_per_minute": rate},
        )
        alerts.append(alert)
        logger.warning(
            "Rate abuse detected for tenant %s: %.1f/min",
            tenant_id,
            rate,
        )


def record_completion(tenant_id: str, scenario_id: str, success: bool) -> None:
    """Record a scenario completion for a tenant."""
    usage = get_or_create_usage(tenant_id)

    if success:
        usage.scenarios_completed += 1
    else:
        usage.scenarios_failed += 1

    if scenario_id in usage.active_scenarios:
        usage.active_scenarios.remove(scenario_id)


async def emit_enforcement_decision(
    tenant_id: str,
    scenario_id: str | None,
    allowed: bool,
    reason: str | None,
) -> None:
    """Publish enforcement decision to NATS."""
    if js:
        try:
            await js.publish(
                "quota.decision",
                json.dumps(
                    {
                        "tenant_id": tenant_id,
                        "scenario_id": scenario_id,
                        "allowed": allowed,
                        "reason": reason,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                ).encode(),
            )
        except Exception as e:
            logger.warning("Failed to publish quota decision: %s", e)


async def process_spawn_request(msg: Any) -> None:
    """Process spawn requests and enforce quotas."""
    try:
        data = json.loads(msg.data.decode())
        tenant_id = data.get("tenant_id", "default")
        scenario_id = data.get("scenario_id")
        track = data.get("track")

        logger.info(
            "Checking quota for tenant=%s scenario=%s track=%s",
            tenant_id,
            scenario_id,
            track,
        )

        result = check_quota(tenant_id, track)

        if result.allowed:
            record_spawn(tenant_id, scenario_id)
            logger.info(
                "Quota check passed for tenant %s (remaining: %d)",
                tenant_id,
                result.remaining,
            )
        else:
            logger.warning(
                "Quota check failed for tenant %s: %s",
                tenant_id,
                result.reason,
            )

        await emit_enforcement_decision(
            tenant_id, scenario_id, result.allowed, result.reason
        )
        await msg.ack()

    except Exception as e:
        logger.exception("Error processing spawn request: %s", e)
        if msg:
            await msg.nak()


async def process_scenario_completed(msg: Any) -> None:
    """Process scenario completion events."""
    try:
        data = json.loads(msg.data.decode())
        tenant_id = data.get("tenant_id", "default")
        scenario_id = data.get("scenario_id")
        success = data.get("success", True)

        record_completion(tenant_id, scenario_id, success)
        logger.info(
            "Recorded completion for tenant=%s scenario=%s success=%s",
            tenant_id,
            scenario_id,
            success,
        )

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing scenario completion: %s", e)
        if msg:
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS events for quota enforcement."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        # Ensure stream exists
        try:
            await js.add_stream(
                name="QUOTA",
                subjects=["quota.*"],
            )
        except Exception:
            pass

        # Subscribe to spawn requests for quota checking
        spawn_config = ConsumerConfig(
            durable_name="metrics_tuner_spawn",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=10,
        )
        await js.subscribe(
            "quota.check",
            cb=process_spawn_request,
            config=spawn_config,
        )

        # Subscribe to scenario completions
        complete_config = ConsumerConfig(
            durable_name="metrics_tuner_complete",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=10,
        )
        await js.subscribe(
            "scenario.completed",
            cb=process_scenario_completed,
            config=complete_config,
        )

        logger.info("Subscribed to quota enforcement streams")

        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logger.error("NATS subscriber error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    task = asyncio.create_task(nats_subscriber())
    logger.info("Metrics tuner started")
    yield
    task.cancel()
    if nc:
        await nc.close()
    logger.info("Metrics tuner stopped")


app = FastAPI(title="FrostGate Forge Metrics Tuner", lifespan=lifespan)


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
    return {"status": "ok", "service": "forge_metrics_tuner"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_metrics_tuner"}


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "service": "forge_metrics_tuner"}


@app.post("/v1/quota/check")
async def api_check_quota(tenant_id: str, track: str | None = None) -> QuotaCheckResult:
    """Check quota for a tenant via API."""
    return check_quota(tenant_id, track)


@app.get("/v1/quota/{tenant_id}")
async def get_tenant_quota(tenant_id: str) -> TenantQuota:
    """Get quota configuration for a tenant."""
    return get_or_create_quota(tenant_id)


@app.put("/v1/quota/{tenant_id}")
async def update_tenant_quota(tenant_id: str, quota: TenantQuota) -> TenantQuota:
    """Update quota configuration for a tenant."""
    quota.tenant_id = tenant_id
    tenant_quotas[tenant_id] = quota
    logger.info("Updated quota for tenant %s", tenant_id)
    return quota


@app.get("/v1/usage/{tenant_id}")
async def get_tenant_usage(tenant_id: str) -> TenantUsage:
    """Get usage statistics for a tenant."""
    if tenant_id not in tenant_usage:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant_usage[tenant_id]


@app.get("/v1/usage")
async def list_usage() -> list[TenantUsage]:
    """List usage for all tenants."""
    return list(tenant_usage.values())


@app.post("/v1/block/{tenant_id}")
async def block_tenant(tenant_id: str, reason: str = "manual block") -> dict:
    """Block a tenant from spawning scenarios."""
    blocked_tenants.add(tenant_id)
    alert = FairnessAlert(
        tenant_id=tenant_id,
        alert_type="manual_block",
        severity="critical",
        message=f"Tenant blocked: {reason}",
    )
    alerts.append(alert)
    logger.warning("Blocked tenant %s: %s", tenant_id, reason)
    return {"status": "blocked", "tenant_id": tenant_id}


@app.post("/v1/unblock/{tenant_id}")
async def unblock_tenant(tenant_id: str) -> dict:
    """Unblock a tenant."""
    blocked_tenants.discard(tenant_id)
    logger.info("Unblocked tenant %s", tenant_id)
    return {"status": "unblocked", "tenant_id": tenant_id}


@app.get("/v1/alerts")
async def get_alerts(
    tenant_id: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> list[FairnessAlert]:
    """Get fairness alerts."""
    result = alerts
    if tenant_id:
        result = [a for a in result if a.tenant_id == tenant_id]
    if severity:
        result = [a for a in result if a.severity == severity]
    return result[-limit:]


@app.get("/v1/stats")
async def get_stats() -> dict:
    """Get aggregate quota enforcement statistics."""
    total_tenants = len(tenant_usage)
    total_scenarios = sum(u.scenarios_started for u in tenant_usage.values())
    active_scenarios = sum(len(u.active_scenarios) for u in tenant_usage.values())
    blocked_count = len(blocked_tenants)
    total_alerts = len(alerts)

    return {
        "total_tenants": total_tenants,
        "total_scenarios_started": total_scenarios,
        "active_scenarios": active_scenarios,
        "blocked_tenants": blocked_count,
        "total_alerts": total_alerts,
        "alerts_by_type": defaultdict(
            int, {a.alert_type: 1 for a in alerts}
        ),
    }
