"""FrostGate Forge Scoreboard Service.

Calculates scores, generates evidence bundles, and produces signed verdicts.
Subscribes to scenario.completed events and stores final scoring artifacts.
"""

from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager, suppress
import contextvars
from dataclasses import dataclass
from datetime import UTC, datetime
import gzip
import hashlib
import hmac
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import random
import tarfile
import time
from typing import Any
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Request
import httpx
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
logger = logging.getLogger("forge_scoreboard")

# Configuration
NATS_URL = os.getenv("NATS_URL", "nats://forge_nats:4222")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "forge_minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "forgeadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "forgeadmin123")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "forge-evidence")
STORAGE_ROOT = Path(os.getenv("STORAGE_ROOT", "storage"))
SIGNING_KEY_PATH = os.getenv("SIGNING_KEY_PATH")


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


# Signing key (in production, load from Vault/KMS)
SIGNING_KEY: ed25519.Ed25519PrivateKey | None = None


class CriterionScore(BaseModel):
    criterion_id: str
    passed: bool
    weight: float = 1.0
    weighted_score: float


class ScoreResult(BaseModel):
    scenario_id: str
    track: str
    subject: str | None = None
    tenant_id: str | None = None
    plan: str | None = None
    retention_days: int | None = None
    score: float  # 0.0 to 1.0
    passed: int
    total: int
    criteria: list[CriterionScore] = Field(default_factory=list)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Verdict(BaseModel):
    scenario_id: str
    score_hash: str
    evidence_hash: str
    computed_at: str
    signature: str


class ScoreboardEntry(BaseModel):
    scenario_id: str
    track: str
    score: ScoreResult
    evidence_url: str
    verdict_url: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScenarioCompletionPayload(BaseModel):
    scenario_id: str
    track: str
    completion_reason: str
    completed_at: datetime
    subject: str | None = None
    tenant_id: str | None = None
    plan: str | None = None
    retention_days: int | None = None
    score: float | None = None
    passed: int | None = None
    total: int | None = None
    criteria: list[dict] = Field(default_factory=list)


# In-memory scoreboard (production would use persistent storage)
scoreboard: dict[str, ScoreboardEntry] = {}

# NATS client
nc: nats.NATS | None = None
js: Any = None

# MinIO client
minio_client: Minio | None = None

try:
    import zstandard as zstd
except ImportError:  # pragma: no cover - optional dependency
    zstd = None


@dataclass(frozen=True)
class EvidenceBundle:
    filename: str
    content_type: str
    payload: bytes


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


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _request_with_retries(
    client: httpx.Client,
    method: str,
    url: str,
    *,
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
            response = client.request(method, url, headers=headers)
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
            _sleep(delay)
    raise httpx.RequestError("request failed") from last_exc


_egress_breaker = CircuitBreaker(
    "egress_gateway", float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))
)


def get_minio_client() -> Minio:
    global minio_client
    if minio_client is None:
        minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False,
        )
        if not minio_client.bucket_exists(MINIO_BUCKET):
            minio_client.make_bucket(MINIO_BUCKET)
    return minio_client


def get_signing_key() -> ed25519.Ed25519PrivateKey:
    """Get or generate signing key."""
    global SIGNING_KEY
    if SIGNING_KEY is None:
        if SIGNING_KEY_PATH:
            key_path = Path(SIGNING_KEY_PATH)
            if not key_path.exists():
                raise FileNotFoundError("SIGNING_KEY_PATH does not exist")
            key_bytes = key_path.read_bytes()
            SIGNING_KEY = serialization.load_pem_private_key(key_bytes, password=None)
        else:
            # In production, load from secure storage
            SIGNING_KEY = ed25519.Ed25519PrivateKey.generate()
            logger.warning("Generated ephemeral signing key - use KMS in production")
    return SIGNING_KEY


def calculate_score(
    criteria_results: list[dict], weights: dict[str, float] | None = None
) -> ScoreResult:
    """Calculate weighted score from criteria results."""
    weights = weights or {}
    criteria_scores = []
    total_weight = 0.0
    weighted_sum = 0.0

    for result in criteria_results:
        criterion_id = result.get("criterion_id", "unknown")
        passed = result.get("passed", False)
        weight = weights.get(criterion_id, 1.0)

        weighted_score = weight if passed else 0.0
        total_weight += weight
        weighted_sum += weighted_score

        criteria_scores.append(
            CriterionScore(
                criterion_id=criterion_id,
                passed=passed,
                weight=weight,
                weighted_score=weighted_score,
            )
        )

    final_score = weighted_sum / total_weight if total_weight > 0 else 0.0
    passed_count = sum(1 for c in criteria_scores if c.passed)

    return ScoreResult(
        scenario_id="",  # Set by caller
        track="",  # Set by caller
        score=final_score,
        passed=passed_count,
        total=len(criteria_scores),
        criteria=criteria_scores,
    )


def _score_json_bytes(score: ScoreResult) -> bytes:
    payload = score.model_dump()
    payload["computed_at"] = score.computed_at.isoformat()
    score_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return score_json.encode("utf-8")


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _audit_payload(entry: dict[str, Any]) -> bytes:
    payload = dict(entry)
    payload.pop("entry_hash", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def audit_log_path(scenario_id: str) -> Path:
    return _results_dir(scenario_id) / "audit.jsonl"


def append_audit_event(
    scenario_id: str,
    event_type: str,
    actor: str,
    correlation_id: str,
    details: dict[str, Any],
) -> None:
    path = audit_log_path(scenario_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = "0" * 64
    if path.exists():
        last_line = ""
        with path.open("r", encoding="utf-8") as handle:
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
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")


def verify_audit_chain(path: Path) -> bool:
    if not path.exists():
        return False
    prev_hash = "0" * 64
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False
            if entry.get("prev_hash") != prev_hash:
                return False
            expected = _hash_bytes(_audit_payload(entry))
            if entry.get("entry_hash") != expected:
                return False
            prev_hash = entry.get("entry_hash")
    return True


def _tar_add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    tar.addfile(info, BytesIO(data))


def _require_internal_auth(request: Request) -> None:
    expected = os.getenv("SCOREBOARD_INTERNAL_TOKEN")
    if not expected:
        logger.error("SCOREBOARD_INTERNAL_TOKEN not configured")
        raise HTTPException(status_code=500, detail="internal auth not configured")
    token = request.headers.get("x-internal-token", "")
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="internal auth required")


def _results_dir(scenario_id: str) -> Path:
    return STORAGE_ROOT / "scenarios" / scenario_id / "results"


def _check_storage_writable() -> None:
    scenarios_dir = STORAGE_ROOT / "scenarios"
    try:
        scenarios_dir.mkdir(parents=True, exist_ok=True)
        test_file = scenarios_dir / ".readyz"
        test_file.write_bytes(b"")
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"storage not writable: {exc}") from exc
    finally:
        test_file = scenarios_dir / ".readyz"
        if test_file.exists():
            test_file.unlink()


def _check_signing_key_ready() -> None:
    try:
        get_signing_key()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"signing key unavailable: {exc}") from exc


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
        with suppress(OSError):
            probe_path.unlink()
        raise HTTPException(status_code=503, detail="filesystem not read-only")


def _check_egress_gateway() -> None:
    egress_url = os.getenv("EGRESS_GATEWAY_URL")
    if not egress_url:
        return
    expected = os.getenv("EGRESS_DRY_RUN_EXPECTED")
    if expected is None:
        forge_env = os.getenv("FORGE_ENV", "dev").lower()
        expected = "true" if forge_env == "dev" else "false"
    with httpx.Client(timeout=_httpx_timeout()) as client:
        try:
            response = _request_with_retries(
                client,
                "GET",
                f"{egress_url}/readyz",
                breaker=_egress_breaker,
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


def _public_key_b64() -> str:
    public_key = get_signing_key().public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("utf-8")


def store_score_artifacts_filesystem(
    scenario_id: str,
    score_bytes: bytes,
    evidence: EvidenceBundle,
    verdict: Verdict,
) -> tuple[str, str, str, str]:
    results_dir = _results_dir(scenario_id)
    results_dir.mkdir(parents=True, exist_ok=True)

    score_path = results_dir / "score.json"
    score_path.write_bytes(score_bytes)

    evidence_path = results_dir / evidence.filename
    evidence_path.write_bytes(evidence.payload)

    verdict_path = results_dir / "verdict.sig"
    verdict_path.write_text(verdict.model_dump_json(indent=2), encoding="utf-8")

    public_key_path = results_dir / "verdict.pub"
    public_key_path.write_text(_public_key_b64(), encoding="utf-8")

    return (
        score_path.as_posix(),
        evidence_path.as_posix(),
        verdict_path.as_posix(),
        public_key_path.as_posix(),
    )


def build_evidence_bundle(
    scenario_id: str,
    track: str,
    source_evidence_url: str,
    artifacts_root: str | None = None,
    audit_path: Path | None = None,
    subject: str | None = None,
    tenant_id: str | None = None,
    plan: str | None = None,
    retention_days: int | None = None,
) -> EvidenceBundle:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        log_payload = (f"scoreboard evidence placeholder for {scenario_id} ({track})\n").encode()
        _tar_add_bytes(tar, "logs/scoreboard.log", log_payload)

        telemetry_payload = json.dumps(
            {"scenario_id": scenario_id, "track": track}, sort_keys=True
        ).encode("utf-8")
        _tar_add_bytes(tar, "telemetry/scoreboard.json", telemetry_payload)

        manifest = {
            "scenario_id": scenario_id,
            "track": track,
            "subject": subject,
            "tenant_id": tenant_id,
            "plan": plan,
            "retention_days": retention_days,
        }

        if audit_path and audit_path.exists():
            audit_bytes = audit_path.read_bytes()
            _tar_add_bytes(tar, "audit/audit.jsonl", audit_bytes)
            manifest["audit_sha256"] = _hash_bytes(audit_bytes)

        _tar_add_bytes(
            tar,
            "manifest.json",
            json.dumps(manifest, sort_keys=True).encode("utf-8"),
        )

        if source_evidence_url:
            _tar_add_bytes(
                tar,
                "source_evidence.txt",
                f"{source_evidence_url}\n".encode(),
            )

        if artifacts_root:
            artifacts_dir = Path(artifacts_root) / scenario_id / "artifacts"
            if artifacts_dir.is_dir():
                for path in sorted(p for p in artifacts_dir.rglob("*") if p.is_file()):
                    relative = path.relative_to(artifacts_dir).as_posix()
                    _tar_add_bytes(tar, f"artifacts/{relative}", path.read_bytes())

    raw_tar = buffer.getvalue()
    if zstd is not None:
        compressor = zstd.ZstdCompressor(level=3)
        payload = compressor.compress(raw_tar)
        return EvidenceBundle(
            filename="evidence.tar.zst",
            content_type="application/zstd",
            payload=payload,
        )

    payload = gzip.compress(raw_tar)
    return EvidenceBundle(
        filename="evidence.tar.gz",
        content_type="application/gzip",
        payload=payload,
    )


def sign_verdict(score_hash: str, evidence_hash: str, scenario_id: str) -> Verdict:
    """Create a signed verdict for a scenario completion."""
    key = get_signing_key()
    computed_at = datetime.now(UTC).isoformat()

    # Create message to sign
    message = f"{score_hash}:{evidence_hash}"
    signature_bytes = key.sign(message.encode())
    signature = base64.b64encode(signature_bytes).decode()

    return Verdict(
        scenario_id=scenario_id,
        score_hash=score_hash,
        evidence_hash=evidence_hash,
        computed_at=computed_at,
        signature=signature,
    )


def build_score_result(payload: ScenarioCompletionPayload) -> ScoreResult:
    if not payload.subject or not payload.tenant_id:
        raise HTTPException(status_code=400, detail="subject and tenant_id required")
    if not payload.plan:
        raise HTTPException(status_code=400, detail="plan required")
    if payload.criteria:
        score = calculate_score(payload.criteria)
        score.scenario_id = payload.scenario_id
        score.track = payload.track
        score.subject = payload.subject
        score.tenant_id = payload.tenant_id
        score.plan = payload.plan
        score.retention_days = payload.retention_days
        return score
    return ScoreResult(
        scenario_id=payload.scenario_id,
        track=payload.track,
        subject=payload.subject,
        tenant_id=payload.tenant_id,
        plan=payload.plan,
        retention_days=payload.retention_days,
        score=payload.score or 0.0,
        passed=payload.passed or 0,
        total=payload.total or 0,
        criteria=payload.criteria,
    )


def finalize_scoring(
    payload: ScenarioCompletionPayload,
    evidence_url: str,
    artifacts_root: str | None,
) -> ScoreboardEntry:
    append_audit_event(
        scenario_id=payload.scenario_id,
        event_type="score.finalized",
        actor=payload.subject or "unknown",
        correlation_id=request_id_ctx.get(),
        details={
            "track": payload.track,
            "tenant_id": payload.tenant_id,
            "completion_reason": payload.completion_reason,
        },
    )
    score = build_score_result(payload)
    score_bytes = _score_json_bytes(score)
    score_hash = _hash_bytes(score_bytes)
    evidence_bundle = build_evidence_bundle(
        payload.scenario_id,
        payload.track,
        evidence_url,
        artifacts_root,
        audit_log_path(payload.scenario_id),
        payload.subject,
        payload.tenant_id,
        payload.plan,
        payload.retention_days,
    )
    evidence_hash = _hash_bytes(evidence_bundle.payload)
    verdict = sign_verdict(score_hash, evidence_hash, payload.scenario_id)

    score_path, evidence_path, verdict_path, _ = store_score_artifacts_filesystem(
        payload.scenario_id,
        score_bytes,
        evidence_bundle,
        verdict,
    )

    entry = ScoreboardEntry(
        scenario_id=payload.scenario_id,
        track=payload.track,
        score=score,
        evidence_url=f"file://{evidence_path}",
        verdict_url=f"file://{verdict_path}",
    )
    scoreboard[payload.scenario_id] = entry
    logger.info("Stored score artifacts for %s", payload.scenario_id)
    return entry


async def process_scenario_completed(msg: Any) -> None:
    """Process scenario.completed events and finalize scoring."""
    try:
        data = json.loads(msg.data.decode())
        scenario_id = data.get("scenario_id")
        track = data.get("track")
        evidence_url = data.get("evidence_url", "")
        subject = data.get("subject")
        tenant_id = data.get("tenant_id")
        plan = data.get("plan") or data.get("tier")
        retention_days = data.get("retention_days")

        logger.info("Processing scenario.completed: %s", scenario_id)

        if not subject or not tenant_id:
            raise RuntimeError("scenario.completed missing subject or tenant_id")

        payload = ScenarioCompletionPayload(
            scenario_id=scenario_id,
            track=track,
            completion_reason=data.get("completion_reason", "nats_event"),
            completed_at=datetime.now(UTC),
            subject=subject,
            tenant_id=tenant_id,
            plan=plan,
            retention_days=retention_days,
            score=data.get("score"),
            passed=data.get("passed"),
            total=data.get("total"),
            criteria=data.get("criteria", []),
        )

        entry = finalize_scoring(
            payload,
            evidence_url,
            os.getenv("SCENARIO_ARTIFACTS_ROOT"),
        )

        logger.info(
            "Finalized score for %s: %.2f (%d/%d)",
            scenario_id,
            entry.score.score,
            entry.score.passed,
            entry.score.total,
        )

        await msg.ack()

    except Exception as e:
        logger.exception("Error processing scenario.completed: %s", e)
        if msg:
            await msg.nak()


async def nats_subscriber() -> None:
    """Subscribe to NATS scenario events."""
    global nc, js

    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        consumer_config = ConsumerConfig(
            durable_name="scoreboard",
            deliver_policy=DeliverPolicy.ALL,
            ack_wait=30,
        )

        await js.subscribe(
            "scenario.completed",
            cb=process_scenario_completed,
            config=consumer_config,
        )
        logger.info("Subscribed to scenario.completed")

        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logger.error("NATS subscriber error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    _enforce_startup_config()
    task = asyncio.create_task(nats_subscriber())
    logger.info("Scoreboard started")
    yield
    task.cancel()
    if nc:
        await nc.close()
    logger.info("Scoreboard stopped")


app = FastAPI(title="FrostGate Forge Scoreboard", lifespan=lifespan)


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
    return {"status": "ok", "service": "forge_scoreboard"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_scoreboard"}


@app.get("/readyz")
def readyz() -> dict:
    _check_read_only_fs()
    _check_egress_gateway()
    _check_storage_writable()
    _check_signing_key_ready()
    return {"status": "ready", "service": "forge_scoreboard"}


@app.post("/internal/scenario/{scenario_id}/score")
async def score_internal(
    scenario_id: str,
    payload: ScenarioCompletionPayload,
    request: Request,
) -> dict:
    _require_internal_auth(request)
    if payload.scenario_id != scenario_id:
        raise HTTPException(status_code=400, detail="scenario_id mismatch")

    logger.info(
        "Internal scoring request: scenario_id=%s reason=%s completed_at=%s",
        scenario_id,
        payload.completion_reason,
        payload.completed_at.isoformat(),
    )

    entry = finalize_scoring(
        payload,
        evidence_url="",
        artifacts_root=os.getenv("SCENARIO_ARTIFACTS_ROOT"),
    )
    results_dir = _results_dir(scenario_id)
    return {
        "scenario_id": scenario_id,
        "status": "scored",
        "results_dir": results_dir.as_posix(),
        "evidence_url": entry.evidence_url,
        "verdict_url": entry.verdict_url,
    }


@app.get("/v1/scores/{scenario_id}")
async def get_score(scenario_id: str) -> ScoreboardEntry:
    """Get score for a scenario."""
    if scenario_id not in scoreboard:
        raise HTTPException(status_code=404, detail="Score not found")
    return scoreboard[scenario_id]


@app.get("/v1/scores")
async def list_scores(track: str | None = None, limit: int = 100) -> list[ScoreboardEntry]:
    """List all scores, optionally filtered by track."""
    entries = list(scoreboard.values())
    if track:
        entries = [e for e in entries if e.track == track]
    # Sort by score descending
    entries.sort(key=lambda e: e.score.score, reverse=True)
    return entries[:limit]


@app.get("/v1/leaderboard/{track}")
async def get_leaderboard(track: str, limit: int = 10) -> list[dict]:
    """Get leaderboard for a specific track."""
    entries = [e for e in scoreboard.values() if e.track == track]
    entries.sort(key=lambda e: e.score.score, reverse=True)

    return [
        {
            "rank": i + 1,
            "scenario_id": e.scenario_id,
            "score": e.score.score,
            "passed": e.score.passed,
            "total": e.score.total,
            "completed_at": e.created_at.isoformat(),
        }
        for i, e in enumerate(entries[:limit])
    ]


@app.get("/v1/stats")
async def get_stats() -> dict:
    """Get aggregate scoring statistics."""
    if not scoreboard:
        return {
            "total_scenarios": 0,
            "by_track": {},
        }

    by_track: dict[str, dict] = {}
    for entry in scoreboard.values():
        track = entry.track
        if track not in by_track:
            by_track[track] = {
                "count": 0,
                "total_score": 0.0,
                "pass_count": 0,
            }
        by_track[track]["count"] += 1
        by_track[track]["total_score"] += entry.score.score
        if entry.score.score >= 0.7:  # 70% threshold for "pass"
            by_track[track]["pass_count"] += 1

    # Calculate averages
    for track_stats in by_track.values():
        count = track_stats["count"]
        track_stats["avg_score"] = track_stats["total_score"] / count if count > 0 else 0
        track_stats["pass_rate"] = track_stats["pass_count"] / count if count > 0 else 0

    return {
        "total_scenarios": len(scoreboard),
        "by_track": by_track,
    }
