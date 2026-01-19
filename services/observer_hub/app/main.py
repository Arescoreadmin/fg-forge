"""FrostGate Forge Observer Hub Service.

Aggregates telemetry from all scenario components, performs PII detection,
manages cardinality, and forwards to Loki/Prometheus.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager, suppress
import contextvars
from datetime import UTC, datetime
import json
import logging
import os
import re
from typing import Any
import uuid

from fastapi import FastAPI, Request
import httpx
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
logger = logging.getLogger("forge_observer_hub")

# Configuration
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
LOKI_URL = os.getenv("LOKI_URL", "http://forge_loki:3100")

# PII patterns for detection
PII_PATTERNS: list[tuple[str, str]] = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"\b\d{16}\b", "CREDIT_CARD"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP_ADDRESS"),
]


class TelemetryEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    service: str
    scenario_id: str | None = None
    track: str | None = None
    level: str = "info"
    message: str
    labels: dict[str, str] = Field(default_factory=dict)
    pii_detected: bool = False
    pii_types: list[str] = Field(default_factory=list)


class MetricEvent(BaseModel):
    name: str
    value: float
    labels: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ObserverStats(BaseModel):
    events_received: int = 0
    events_forwarded: int = 0
    pii_detections: int = 0
    events_by_service: dict[str, int] = Field(default_factory=dict)
    events_by_level: dict[str, int] = Field(default_factory=dict)


# Stats tracking
stats = ObserverStats()

# Cardinality tracking
label_cardinality: dict[str, set[str]] = defaultdict(set)
MAX_CARDINALITY = 1000

# NATS client
nc: nats.NATS | None = None
js: Any = None


def detect_pii(text: str) -> tuple[bool, list[str]]:
    """Detect potential PII in text."""
    detected_types: list[str] = []
    for pattern, pii_type in PII_PATTERNS:
        if re.search(pattern, text):
            detected_types.append(pii_type)
    return bool(detected_types), detected_types


def scrub_pii(text: str) -> str:
    """Redact PII from text."""
    result = text
    for pattern, pii_type in PII_PATTERNS:
        result = re.sub(pattern, f"[REDACTED:{pii_type}]", result)
    return result


def check_cardinality(labels: dict[str, str]) -> bool:
    """Check if adding these labels would exceed cardinality limits."""
    for key, value in labels.items():
        if len(label_cardinality[key]) >= MAX_CARDINALITY and value not in label_cardinality[key]:
            return False
        label_cardinality[key].add(value)
    return True


async def forward_to_loki(event: TelemetryEvent) -> bool:
    """Forward log event to Loki."""
    if not LOKI_URL:
        return False

    # Prepare Loki push format
    labels: dict[str, str] = {
        "service": event.service,
        "level": event.level,
    }
    if event.scenario_id:
        labels["scenario_id"] = event.scenario_id
    if event.track:
        labels["track"] = event.track

    # Check cardinality
    if not check_cardinality(labels):
        logger.warning("Cardinality limit reached, dropping labels")
        labels = {"service": event.service, "level": event.level}

    payload = {
        "streams": [
            {
                "stream": labels,
                "values": [[str(int(event.timestamp.timestamp() * 1e9)), event.message]],
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{LOKI_URL}/loki/api/v1/push",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            return response.status_code < 400
    except Exception as exc:
        logger.debug("Failed to forward to Loki: %s", exc)
        return False


async def process_telemetry_log(msg: Any) -> None:
    """Process incoming telemetry log events."""
    try:
        data = json.loads(msg.data.decode("utf-8"))
        stats.events_received += 1

        # Create event
        event = TelemetryEvent(
            service=data.get("service", "unknown"),
            scenario_id=data.get("scenario_id"),
            track=data.get("track"),
            level=data.get("level", "info"),
            message=data.get("message", ""),
            labels=data.get("labels", {}),
        )

        # Track by service
        stats.events_by_service[event.service] = stats.events_by_service.get(event.service, 0) + 1

        # Track by level
        stats.events_by_level[event.level] = stats.events_by_level.get(event.level, 0) + 1

        # Detect PII
        pii_found, pii_types = detect_pii(event.message)
        if pii_found:
            event.pii_detected = True
            event.pii_types = pii_types
            event.message = scrub_pii(event.message)
            stats.pii_detections += 1
            logger.warning("PII detected in event from %s: %s", event.service, pii_types)

        # Forward to Loki
        if await forward_to_loki(event):
            stats.events_forwarded += 1

        await msg.ack()

    except Exception as exc:
        logger.exception("Error processing telemetry log: %s", exc)
        with suppress(Exception):
            await msg.nak()


async def process_telemetry_metrics(msg: Any) -> None:
    """Process incoming metric events."""
    try:
        data = json.loads(msg.data.decode("utf-8"))

        metric = MetricEvent(
            name=data.get("name", "unknown"),
            value=data.get("value", 0.0),
            labels=data.get("labels", {}),
        )

        # For now, just log metrics (would push to Prometheus gateway)
        logger.debug("Metric: %s=%f labels=%s", metric.name, metric.value, metric.labels)

        await msg.ack()

    except Exception as exc:
        logger.exception("Error processing telemetry metrics: %s", exc)
        with suppress(Exception):
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS telemetry events."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        # Create telemetry stream
        with suppress(Exception):
            await js.add_stream(name="TELEMETRY", subjects=["telemetry.*"])

        # Subscribe to logs
        log_config = ConsumerConfig(
            durable_name="observer_logs",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=10,
        )
        await js.subscribe(
            "telemetry.logs",
            cb=process_telemetry_log,
            config=log_config,
        )

        # Subscribe to metrics
        metrics_config = ConsumerConfig(
            durable_name="observer_metrics",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=10,
        )
        await js.subscribe(
            "telemetry.metrics",
            cb=process_telemetry_metrics,
            config=metrics_config,
        )

        logger.info("Subscribed to telemetry streams")

        while True:
            await asyncio.sleep(1)

    except Exception as exc:
        logger.error("NATS subscriber error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    task = asyncio.create_task(nats_subscriber())
    logger.info("Observer hub started")
    try:
        yield
    finally:
        task.cancel()
        if nc:
            await nc.close()
        logger.info("Observer hub stopped")


app = FastAPI(title="FrostGate Forge Observer Hub", lifespan=lifespan)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = (
        request.headers.get("x-request-id")
        or request.headers.get("x-correlation-id")
        or str(uuid.uuid4())
    )
    token = request_id_ctx.set(request_id)
    try:
        response = await call_next(request)
    finally:
        request_id_ctx.reset(token)
    response.headers["x-request-id"] = request_id
    return response


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_observer_hub"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_observer_hub"}


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "service": "forge_observer_hub"}


@app.get("/v1/stats")
async def get_stats() -> ObserverStats:
    """Get observer hub statistics."""
    return stats


@app.get("/v1/cardinality")
async def get_cardinality() -> dict:
    """Get label cardinality information."""
    return {key: len(values) for key, values in label_cardinality.items()}


@app.post("/v1/log")
async def post_log(event: TelemetryEvent) -> dict:
    """Direct log submission endpoint."""
    stats.events_received += 1

    # Detect and scrub PII
    pii_found, pii_types = detect_pii(event.message)
    if pii_found:
        event.pii_detected = True
        event.pii_types = pii_types
        event.message = scrub_pii(event.message)
        stats.pii_detections += 1

    # Forward to Loki
    if await forward_to_loki(event):
        stats.events_forwarded += 1
        return {"status": "forwarded"}

    return {"status": "received", "forwarded": False}
