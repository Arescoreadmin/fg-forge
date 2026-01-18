"""FrostGate Forge Overlay Sanitizer Service.

PII scrubbing and audit sanitization service. Applies allowlist-based scrubbing
for evidence artifacts and generates signed audit bundles for compliance exports.
"""

from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
import contextvars
from datetime import UTC, datetime
from enum import Enum
import hashlib
import io
import json
import logging
import os
import re
from typing import Any
import uuid
import zipfile

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from minio import Minio
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
logger = logging.getLogger("forge_overlay_sanitizer")

# Configuration
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "forge_minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "forgeadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "forgeadmin123")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "forge-evidence")
SANITIZED_BUCKET = os.getenv("SANITIZED_BUCKET", "forge-sanitized")


class SanitizationLevel(str, Enum):
    MINIMAL = "minimal"  # Only obvious PII
    STANDARD = "standard"  # PII + internal identifiers
    STRICT = "strict"  # All potentially sensitive data


class PIIType(str, Enum):
    EMAIL = "email"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    PASSWORD = "password"
    NAME = "name"
    ADDRESS = "address"


# PII detection patterns
PII_PATTERNS = {
    PIIType.EMAIL: (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "[REDACTED:EMAIL]",
    ),
    PIIType.SSN: (
        r"\b\d{3}-\d{2}-\d{4}\b",
        "[REDACTED:SSN]",
    ),
    PIIType.CREDIT_CARD: (
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "[REDACTED:CC]",
    ),
    PIIType.PHONE: (
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "[REDACTED:PHONE]",
    ),
    PIIType.IP_ADDRESS: (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "[REDACTED:IP]",
    ),
    PIIType.API_KEY: (
        r"\b(?:api[_-]?key|apikey|secret[_-]?key)[=:\s]+['\"]?[\w-]{20,}['\"]?",
        "[REDACTED:API_KEY]",
    ),
    PIIType.PASSWORD: (
        r"\b(?:password|passwd|pwd)[=:\s]+['\"]?[^\s'\"]{4,}['\"]?",
        "[REDACTED:PASSWORD]",
    ),
}

# Allowlist patterns (things to preserve)
ALLOWLIST_PATTERNS = [
    r"forge_scn_\w+",  # Scenario IDs
    r"scn-\w+",  # Scenario IDs
    r"10\.0\.0\.\d+",  # Internal IPs (10.0.0.x)
    r"172\.1[6-9]\.\d+\.\d+",  # Internal IPs (172.16-19.x.x)
    r"172\.2\d\.\d+\.\d+",  # Internal IPs (172.20-29.x.x)
    r"172\.3[0-1]\.\d+\.\d+",  # Internal IPs (172.30-31.x.x)
    r"192\.168\.\d+\.\d+",  # Internal IPs (192.168.x.x)
]


class SanitizationRequest(BaseModel):
    scenario_id: str
    level: SanitizationLevel = SanitizationLevel.STANDARD
    pii_types: list[PIIType] = Field(default_factory=list)
    custom_patterns: list[str] = Field(default_factory=list)
    preserve_patterns: list[str] = Field(default_factory=list)


class SanitizationResult(BaseModel):
    request_id: str = Field(default_factory=lambda: f"san-{uuid.uuid4().hex[:12]}")
    scenario_id: str
    original_hash: str
    sanitized_hash: str
    pii_found: dict[str, int] = Field(default_factory=dict)
    files_processed: int = 0
    total_redactions: int = 0
    sanitized_url: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditBundle(BaseModel):
    bundle_id: str = Field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:12]}")
    scenario_id: str
    sanitization_result: SanitizationResult
    content_hash: str
    signature: str
    signed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    export_url: str | None = None


class SanitizerStats(BaseModel):
    total_requests: int = 0
    files_processed: int = 0
    total_redactions: int = 0
    bundles_created: int = 0
    pii_by_type: dict[str, int] = Field(default_factory=dict)


# In-memory stores
sanitization_results: dict[str, SanitizationResult] = {}
audit_bundles: dict[str, AuditBundle] = {}
stats = SanitizerStats()

# Signing key
SIGNING_KEY: ed25519.Ed25519PrivateKey | None = None

# NATS client
nc: nats.NATS | None = None
js: Any = None

# MinIO client
minio_client: Minio | None = None


def get_minio_client() -> Minio:
    """Get or create MinIO client."""
    global minio_client
    if minio_client is None:
        minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False,
        )
        # Ensure buckets exist
        for bucket in [MINIO_BUCKET, SANITIZED_BUCKET]:
            if not minio_client.bucket_exists(bucket):
                minio_client.make_bucket(bucket)
    return minio_client


def get_signing_key() -> ed25519.Ed25519PrivateKey:
    """Get or generate signing key."""
    global SIGNING_KEY
    if SIGNING_KEY is None:
        SIGNING_KEY = ed25519.Ed25519PrivateKey.generate()
        logger.warning("Generated ephemeral sanitizer signing key - use KMS in production")
    return SIGNING_KEY


def is_allowlisted(text: str, additional_patterns: list[str] | None = None) -> bool:
    """Check if text matches allowlist patterns."""
    patterns = ALLOWLIST_PATTERNS + (additional_patterns or [])
    for pattern in patterns:
        if re.fullmatch(pattern, text):
            return True
    return False


def sanitize_text(
    text: str,
    level: SanitizationLevel,
    pii_types: list[PIIType] | None = None,
    custom_patterns: list[str] | None = None,
    preserve_patterns: list[str] | None = None,
) -> tuple[str, dict[str, int]]:
    """Sanitize text content and return redaction counts."""
    redactions: dict[str, int] = {}
    result = text

    # Determine which PII types to check
    types_to_check = pii_types if pii_types else list(PIIType)

    if level == SanitizationLevel.MINIMAL:
        types_to_check = [PIIType.SSN, PIIType.CREDIT_CARD, PIIType.PASSWORD]
    elif level == SanitizationLevel.STRICT:
        types_to_check = list(PIIType)

    # Apply PII patterns
    for pii_type in types_to_check:
        if pii_type not in PII_PATTERNS:
            continue

        pattern, replacement = PII_PATTERNS[pii_type]

        # Find all matches
        matches = re.findall(pattern, result, re.IGNORECASE)
        for match in matches:
            # Check allowlist
            if is_allowlisted(match, preserve_patterns):
                continue
            redactions[pii_type.value] = redactions.get(pii_type.value, 0) + 1

        # Apply redaction
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    # Apply custom patterns
    if custom_patterns:
        for i, pattern in enumerate(custom_patterns):
            try:
                matches = re.findall(pattern, result)
                if matches:
                    redactions[f"custom_{i}"] = len(matches)
                result = re.sub(pattern, f"[REDACTED:CUSTOM_{i}]", result)
            except re.error as e:
                logger.warning("Invalid custom pattern %s: %s", pattern, e)

    return result, redactions


def sanitize_json(
    data: dict | list,
    level: SanitizationLevel,
    **kwargs: Any,
) -> tuple[dict | list, dict[str, int]]:
    """Recursively sanitize JSON data."""
    total_redactions: dict[str, int] = {}

    def process(obj: Any) -> Any:
        if isinstance(obj, str):
            sanitized, redactions = sanitize_text(obj, level, **kwargs)
            for k, v in redactions.items():
                total_redactions[k] = total_redactions.get(k, 0) + v
            return sanitized
        elif isinstance(obj, dict):
            return {k: process(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [process(item) for item in obj]
        return obj

    return process(data), total_redactions


def create_content_hash(content: bytes) -> str:
    """Create SHA-256 hash of content."""
    return hashlib.sha256(content).hexdigest()


def sign_bundle(bundle_id: str, content_hash: str, scenario_id: str) -> str:
    """Sign an audit bundle."""
    key = get_signing_key()
    message = f"{bundle_id}:{scenario_id}:{content_hash}"
    signature = key.sign(message.encode())
    return base64.b64encode(signature).decode()


async def sanitize_scenario_evidence(
    scenario_id: str,
    request: SanitizationRequest,
) -> SanitizationResult:
    """Sanitize all evidence for a scenario."""
    client = get_minio_client()
    stats.total_requests += 1

    # List objects for scenario
    objects = list(client.list_objects(MINIO_BUCKET, prefix=f"{scenario_id}/"))

    total_redactions: dict[str, int] = {}
    files_processed = 0
    original_content = b""
    sanitized_content = b""

    for obj in objects:
        try:
            # Get object
            response = client.get_object(MINIO_BUCKET, obj.object_name)
            content = response.read()
            original_content += content
            response.close()

            # Determine content type and sanitize
            if obj.object_name.endswith(".json"):
                data = json.loads(content.decode("utf-8"))
                sanitized_data, redactions = sanitize_json(
                    data,
                    request.level,
                    pii_types=request.pii_types,
                    custom_patterns=request.custom_patterns,
                    preserve_patterns=request.preserve_patterns,
                )
                sanitized_bytes = json.dumps(sanitized_data, indent=2).encode("utf-8")
            else:
                # Treat as text
                text = content.decode("utf-8", errors="replace")
                sanitized_text, redactions = sanitize_text(
                    text,
                    request.level,
                    pii_types=request.pii_types,
                    custom_patterns=request.custom_patterns,
                    preserve_patterns=request.preserve_patterns,
                )
                sanitized_bytes = sanitized_text.encode("utf-8")

            sanitized_content += sanitized_bytes

            # Merge redaction counts
            for k, v in redactions.items():
                total_redactions[k] = total_redactions.get(k, 0) + v

            # Store sanitized object
            sanitized_object = f"{scenario_id}/{obj.object_name.split('/')[-1]}"
            client.put_object(
                SANITIZED_BUCKET,
                sanitized_object,
                io.BytesIO(sanitized_bytes),
                len(sanitized_bytes),
            )

            files_processed += 1
            stats.files_processed += 1

        except Exception as e:
            logger.warning("Failed to sanitize %s: %s", obj.object_name, e)

    # Update stats
    for k, v in total_redactions.items():
        stats.pii_by_type[k] = stats.pii_by_type.get(k, 0) + v
        stats.total_redactions += v

    result = SanitizationResult(
        scenario_id=scenario_id,
        original_hash=create_content_hash(original_content),
        sanitized_hash=create_content_hash(sanitized_content),
        pii_found=total_redactions,
        files_processed=files_processed,
        total_redactions=sum(total_redactions.values()),
        sanitized_url=f"s3://{SANITIZED_BUCKET}/{scenario_id}/",
    )

    sanitization_results[result.request_id] = result
    return result


async def create_audit_bundle(
    scenario_id: str,
    sanitization_result: SanitizationResult,
) -> AuditBundle:
    """Create a signed audit bundle for export."""
    client = get_minio_client()
    stats.bundles_created += 1

    # Create ZIP archive of sanitized evidence
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add sanitized files
        objects = list(client.list_objects(SANITIZED_BUCKET, prefix=f"{scenario_id}/"))
        for obj in objects:
            response = client.get_object(SANITIZED_BUCKET, obj.object_name)
            content = response.read()
            response.close()

            filename = obj.object_name.split("/")[-1]
            zf.writestr(filename, content)

        # Add manifest
        manifest = {
            "scenario_id": scenario_id,
            "sanitization": sanitization_result.model_dump(mode="json"),
            "created_at": datetime.now(UTC).isoformat(),
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    # Get bundle content
    zip_buffer.seek(0)
    bundle_content = zip_buffer.read()
    content_hash = create_content_hash(bundle_content)

    # Create bundle
    bundle = AuditBundle(
        scenario_id=scenario_id,
        sanitization_result=sanitization_result,
        content_hash=content_hash,
        signature="",  # Will be set below
    )

    # Sign the bundle
    bundle.signature = sign_bundle(bundle.bundle_id, content_hash, scenario_id)

    # Store bundle
    bundle_object = f"bundles/{bundle.bundle_id}.zip"
    client.put_object(
        SANITIZED_BUCKET,
        bundle_object,
        io.BytesIO(bundle_content),
        len(bundle_content),
        content_type="application/zip",
    )
    bundle.export_url = f"s3://{SANITIZED_BUCKET}/{bundle_object}"

    audit_bundles[bundle.bundle_id] = bundle
    return bundle


async def process_sanitization_request(msg: Any) -> None:
    """Process sanitization requests from NATS."""
    try:
        data = json.loads(msg.data.decode())
        scenario_id = data.get("scenario_id")

        request = SanitizationRequest(
            scenario_id=scenario_id,
            level=SanitizationLevel(data.get("level", "standard")),
            pii_types=[PIIType(t) for t in data.get("pii_types", [])],
            custom_patterns=data.get("custom_patterns", []),
            preserve_patterns=data.get("preserve_patterns", []),
        )

        logger.info(
            "Processing sanitization request for scenario %s (level: %s)",
            scenario_id,
            request.level.value,
        )

        result = await sanitize_scenario_evidence(scenario_id, request)

        # Publish result
        if js:
            await js.publish(
                "sanitization.completed",
                json.dumps(
                    {
                        "request_id": result.request_id,
                        "scenario_id": scenario_id,
                        "total_redactions": result.total_redactions,
                        "sanitized_url": result.sanitized_url,
                    }
                ).encode(),
            )

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing sanitization request: %s", e)
        if msg:
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS sanitization events."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        # Subscribe to sanitization requests
        config = ConsumerConfig(
            durable_name="overlay_sanitizer",
            deliver_policy=DeliverPolicy.NEW,
            ack_wait=60,
        )
        await js.subscribe(
            "sanitization.request",
            cb=process_sanitization_request,
            config=config,
        )

        logger.info("Subscribed to sanitization requests")

        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logger.error("NATS subscriber error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    get_signing_key()
    task = asyncio.create_task(nats_subscriber())
    logger.info("Overlay Sanitizer started")
    yield
    task.cancel()
    if nc:
        await nc.close()
    logger.info("Overlay Sanitizer stopped")


app = FastAPI(title="FrostGate Forge Overlay Sanitizer", lifespan=lifespan)


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
    return {"status": "ok", "service": "forge_overlay_sanitizer"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_overlay_sanitizer"}


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "service": "forge_overlay_sanitizer"}


@app.post("/v1/sanitize")
async def sanitize(request: SanitizationRequest) -> SanitizationResult:
    """Sanitize evidence for a scenario."""
    return await sanitize_scenario_evidence(request.scenario_id, request)


@app.post("/v1/sanitize/text")
async def sanitize_text_endpoint(
    text: str,
    level: SanitizationLevel = SanitizationLevel.STANDARD,
) -> dict:
    """Sanitize a text string (for testing)."""
    sanitized, redactions = sanitize_text(text, level)
    return {
        "original": text,
        "sanitized": sanitized,
        "redactions": redactions,
    }


@app.get("/v1/results/{request_id}")
async def get_result(request_id: str) -> SanitizationResult:
    """Get sanitization result."""
    if request_id not in sanitization_results:
        raise HTTPException(status_code=404, detail="Result not found")
    return sanitization_results[request_id]


@app.get("/v1/results")
async def list_results(
    scenario_id: str | None = None,
    limit: int = 100,
) -> list[SanitizationResult]:
    """List sanitization results."""
    results = list(sanitization_results.values())
    if scenario_id:
        results = [r for r in results if r.scenario_id == scenario_id]
    return results[-limit:]


@app.post("/v1/bundles/{scenario_id}")
async def create_bundle(scenario_id: str) -> AuditBundle:
    """Create an audit bundle for a scenario."""
    # Find most recent sanitization result for scenario
    results = [r for r in sanitization_results.values() if r.scenario_id == scenario_id]
    if not results:
        raise HTTPException(
            status_code=404,
            detail="No sanitization result found for scenario",
        )

    latest_result = max(results, key=lambda r: r.created_at)
    return await create_audit_bundle(scenario_id, latest_result)


@app.get("/v1/bundles/{bundle_id}")
async def get_bundle(bundle_id: str) -> AuditBundle:
    """Get an audit bundle."""
    if bundle_id not in audit_bundles:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return audit_bundles[bundle_id]


@app.get("/v1/bundles/{bundle_id}/download")
async def download_bundle(bundle_id: str) -> StreamingResponse:
    """Download an audit bundle."""
    if bundle_id not in audit_bundles:
        raise HTTPException(status_code=404, detail="Bundle not found")
    client = get_minio_client()

    # Get bundle from MinIO
    bundle_object = f"bundles/{bundle_id}.zip"
    response = client.get_object(SANITIZED_BUCKET, bundle_object)

    return StreamingResponse(
        response,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={bundle_id}.zip"},
    )


@app.get("/v1/bundles")
async def list_bundles(
    scenario_id: str | None = None,
    limit: int = 100,
) -> list[AuditBundle]:
    """List audit bundles."""
    bundles = list(audit_bundles.values())
    if scenario_id:
        bundles = [b for b in bundles if b.scenario_id == scenario_id]
    return bundles[-limit:]


@app.get("/v1/stats")
async def get_stats() -> SanitizerStats:
    """Get sanitizer statistics."""
    return stats


@app.get("/v1/pii-types")
async def list_pii_types() -> list[dict]:
    """List supported PII types."""
    return [
        {"type": pii_type.value, "pattern": pattern}
        for pii_type, (pattern, _) in PII_PATTERNS.items()
    ]
