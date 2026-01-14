from __future__ import annotations
import traceback

import base64
import contextvars
import hmac
import json
import logging
import os
import random
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests
import yaml
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
# -------------------------------------------------------------------
# Import entitlements in a way that survives BOTH:
# 1) normal package import: services.spawn_service.app.main
# 2) dumb test loader: spec_from_file_location(main.py) (no package context)
# -------------------------------------------------------------------
try:
    from .entitlements import (
        EntitlementDecision,
        EntitlementResolver,
        append_billing_audit_event,
        mint_entitlement_token,
        normalize_tier,
        verify_et,
    )
except ImportError:
    import sys

    # Make "app.*" importable when this file is loaded as a standalone module.
    # __file__ = .../services/spawn_service/app/main.py
    spawn_service_root = Path(__file__).resolve().parent.parent  # .../services/spawn_service
    if str(spawn_service_root) not in sys.path:
        sys.path.insert(0, str(spawn_service_root))

    from app.entitlements import (  # type: ignore
        EntitlementDecision,
        EntitlementResolver,
        append_billing_audit_event,
        mint_entitlement_token,
        normalize_tier,
        verify_et,
    )

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    yield
    # shutdown

app = FastAPI(title="FrostGate Forge Spawn Service", lifespan=lifespan)

logger = logging.getLogger("forge_spawn_service")

_warned_sat_secret_alias = False


@app.middleware("http")
async def dump_exceptions(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception:
        logger.error("UNHANDLED EXCEPTION:\n%s", traceback.format_exc())
        raise


def _forge_env() -> str:
    return os.getenv("FORGE_ENV", "dev").lower()


_sat_secret_warning_emitted = False
_fallback_warning_emitted = False

# Ensure this symbol exists deterministically for request handlers/tests.
entitlement_resolver = EntitlementResolver()

TRACKS = {"netplus", "ccna", "cissp"}
TRACK_TEMPLATE = {
    "netplus": "netplus.yaml",
    "ccna": "ccna.yaml",
    "cissp": "cissp.yaml",
}


@dataclass(frozen=True)
class PlanEntitlements:
    max_spawns_per_minute: int
    max_concurrent_scenarios: int
    allowed_tracks: frozenset[str]


PLAN_ENTITLEMENTS: dict[str, PlanEntitlements] = {
    "FREE": PlanEntitlements(
        max_spawns_per_minute=5,
        max_concurrent_scenarios=1,
        allowed_tracks=frozenset({"netplus"}),
    ),
    "PRO": PlanEntitlements(
        max_spawns_per_minute=20,
        max_concurrent_scenarios=3,
        allowed_tracks=frozenset({"netplus", "ccna"}),
    ),
    "TEAM": PlanEntitlements(
        max_spawns_per_minute=60,
        max_concurrent_scenarios=10,
        allowed_tracks=frozenset({"netplus", "ccna", "cissp"}),
    ),
    "ENTERPRISE": PlanEntitlements(
        max_spawns_per_minute=200,
        max_concurrent_scenarios=50,
        allowed_tracks=frozenset(TRACKS),
    ),
}

TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", "/templates"))
REQUEST_CACHE: Dict[str, dict] = {}
CLIENT_ID_HEADER = os.getenv("CLIENT_ID_HEADER", "x-client-id")
TENANT_ID_HEADER = os.getenv("TENANT_ID_HEADER", "x-tenant-id")
ENTITLEMENT_RECEIPT_HEADER = os.getenv("ENTITLEMENT_RECEIPT_HEADER", "x-receipt-token")
_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET")
if not _TOKEN_SECRET:
    forge_env = os.getenv("FORGE_ENV", "dev").lower()
    if forge_env in {"dev", "development"}:
        _TOKEN_SECRET = uuid.uuid4().hex
        logger.warning("ACCESS_TOKEN_SECRET not set; generated ephemeral secret")
    else:
        raise RuntimeError("ACCESS_TOKEN_SECRET not configured")


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
    if env in {"staging", "prod", "production"}:
        if os.getenv("DEV_ALLOW_XPLAN", "false").lower() == "true":
            raise RuntimeError("DEV_ALLOW_XPLAN is not allowed in staging/prod")
        if os.getenv("ALLOW_FREE_DEFAULT", "false").lower() == "true":
            raise RuntimeError("ALLOW_FREE_DEFAULT is not allowed in staging/prod")


@app.on_event("startup")
def warn_deprecated_sat_secret() -> None:
    _enforce_startup_config()
    if os.getenv("SAT_SECRET") and not os.getenv("SAT_HMAC_SECRET"):
        _warn_sat_secret_alias_once()
    yield
    # --- shutdown ---
    return


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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

_warned_sat_secret_alias = False


def _warn_sat_secret_alias() -> None:
    # Warn only once per process to avoid log spam in high-traffic paths.
    global _warned_sat_secret_alias
    if _warned_sat_secret_alias:
        return
    _warned_sat_secret_alias = True
    logging.getLogger("forge_spawn_service").warning(
        "SAT_SECRET is deprecated; use SAT_HMAC_SECRET instead"
    )


def _get_sat_secret() -> str:
    sat_secret = os.getenv("SAT_HMAC_SECRET")
    if sat_secret:
        return sat_secret
    legacy_secret = os.getenv("SAT_SECRET")
    if legacy_secret:
        _warn_sat_secret_alias()
        return legacy_secret
    raise HTTPException(status_code=500, detail="SAT secret not configured")


def _warn_sat_secret_alias_once() -> None:
    global _warned_sat_secret_alias
    if _warned_sat_secret_alias:
        return
    _warned_sat_secret_alias = True
    logger.warning("SAT_SECRET is deprecated; use SAT_HMAC_SECRET instead")


def _sat_issued_at() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _sat_expiration(issued_at: int) -> int:
    ttl_seconds = int(os.getenv("SAT_TTL_SECONDS", "300"))
    return issued_at + ttl_seconds


def generate_access_token(payload: AccessTokenPayload) -> str:
    payload_json = payload.model_dump_json()
    payload_encoded = _b64url_encode(payload_json.encode("utf-8"))
    signature = hmac.new(
        _TOKEN_SECRET.encode("utf-8"), payload_encoded.encode("utf-8"), "sha256"
    ).digest()
    signature_encoded = _b64url_encode(signature)
    return f"{payload_encoded}.{signature_encoded}"


def verify_access_token(token: str) -> AccessTokenPayload:
    try:
        payload_encoded, signature_encoded = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc

    expected_signature = hmac.new(
        _TOKEN_SECRET.encode("utf-8"), payload_encoded.encode("utf-8"), "sha256"
    ).digest()
    expected_encoded = _b64url_encode(expected_signature)
    if not hmac.compare_digest(expected_encoded, signature_encoded):
        raise HTTPException(status_code=401, detail="invalid token")

    try:
        payload = AccessTokenPayload.model_validate(
            json.loads(_b64url_decode(payload_encoded))
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc

    expires_at = datetime.fromisoformat(payload.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="token expired")

    return payload


def generate_sat(payload: SatClaims) -> str:
    header = {"alg": "HS256", "typ": "SAT"}
    header_encoded = _b64url_encode(json.dumps(header).encode("utf-8"))
    payload_encoded = _b64url_encode(payload.model_dump_json().encode("utf-8"))
    try:
        header = json.loads(_b64url_decode(header_encoded))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=401, detail="invalid spawn authorization"
        ) from exc

    if header.get("alg") != "HS256" or header.get("typ") != "SAT":
        raise HTTPException(status_code=401, detail="invalid spawn authorization")

    signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
    signature = hmac.new(
        _get_sat_secret().encode("utf-8"), signing_input, "sha256"
    ).digest()
    signature_encoded = _b64url_encode(signature)
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_sat(token: str) -> SatClaims:
    try:
        header_encoded, payload_encoded, signature_encoded = token.split(".", 2)
    except ValueError as exc:
        raise HTTPException(
            status_code=401, detail="invalid spawn authorization"
        ) from exc

    signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
    expected_signature = hmac.new(
        _get_sat_secret().encode("utf-8"), signing_input, "sha256"
    ).digest()
    expected_encoded = _b64url_encode(expected_signature)
    if not hmac.compare_digest(expected_encoded, signature_encoded):
        raise HTTPException(status_code=401, detail="invalid spawn authorization")

    try:
        payload = SatClaims.model_validate(json.loads(_b64url_decode(payload_encoded)))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=401, detail="invalid spawn authorization"
        ) from exc

    now = int(datetime.now(timezone.utc).timestamp())
    if payload.iat > payload.exp:
        raise HTTPException(status_code=401, detail="invalid spawn authorization")
    if payload.exp < now:
        raise HTTPException(status_code=401, detail="spawn authorization expired")

    return payload


def parse_bearer_token(value: str) -> Optional[str]:
    if not value:
        return None
    parts = value.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def resolve_entitlements(tier: str) -> PlanEntitlements:
    normalized = normalize_tier(tier)
    entitlements = PLAN_ENTITLEMENTS.get(normalized)
    if not entitlements:
        raise HTTPException(status_code=403, detail="unknown tier")
    return entitlements


def enforce_spawn_authorization(request: Request) -> Optional[SatClaims]:
    sat_required = os.getenv("SAT_REQUIRED", "false").lower() == "true"
    token = request.headers.get("x-sat")
    if not token:
        token = parse_bearer_token(request.headers.get("authorization", ""))

    if not token:
        if sat_required:
            raise HTTPException(status_code=401, detail="spawn authorization required")
        return None

    return verify_sat(token)


class SpawnRequest(BaseModel):
    track: str = Field(..., description="Training track identifier")
    subject: str = Field(..., description="User or session identifier")
    tier: Optional[str] = Field(None, description="Billing tier (deprecated)")
    template_id: Optional[str] = Field(None, description="Template identifier override")
    requested_limits: Optional[dict[str, int]] = Field(
        None, description="Requested resource limits"
    )
    scenario_id: Optional[str] = Field(
        None, description="Optional pre-allocated scenario id"
    )
    request_id: Optional[str] = Field(
        None, description="Client-supplied idempotency key"
    )


class SpawnResponse(BaseModel):
    request_id: str
    scenario_id: str
    access_url: str
    access_token: str
    expires_at: str
    sat: str


class AccessTokenPayload(BaseModel):
    scenario_id: str
    request_id: str
    track: str
    expires_at: str


class SatClaims(BaseModel):
    jti: str
    exp: int
    iat: int
    track: str
    template_id: str
    subject: str
    tenant_id: str
    tier: str
    retention_days: Optional[int] = None
    requested_limits: Optional[dict[str, int]] = None
    scenario_id: Optional[str] = None


class RateLimitState:
    def __init__(self, count: int, reset_at: float) -> None:
        self.count = count
        self.reset_at = reset_at


class SpawnLimiter:
    def __init__(self) -> None:
        self._redis_url = os.getenv("REDIS_URL")
        self._redis_required = bool(self._redis_url)
        self._redis_client = None
        self._lock = threading.Lock()
        self._rate_cache: dict[str, RateLimitState] = {}
        self._active_cache: dict[str, dict[str, float]] = {}

    def _get_redis(self):
        global _fallback_warning_emitted
        if not self._redis_url:
            if not _fallback_warning_emitted:
                logger.warning("REDIS_URL not set; using in-memory rate limits (dev only)")
                _fallback_warning_emitted = True
            return None
        if self._redis_client is None:
            import redis

            try:
                self._redis_client = redis.from_url(
                    self._redis_url,
                    decode_responses=True,
                    socket_connect_timeout=float(
                        os.getenv("REDIS_CONNECT_TIMEOUT_SECONDS", "1.0")
                    ),
                    socket_timeout=float(os.getenv("REDIS_TIMEOUT_SECONDS", "1.0")),
                )
            except Exception as exc:
                logger.warning("Redis client init failed: %s", exc)
                if self._redis_required:
                    raise HTTPException(status_code=503, detail="redis unavailable") from exc
                return None
        return self._redis_client

    def check_rate_limit(self, subject: str, limit: int) -> None:
        if limit <= 0:
            return
        now = time.time()
        client = self._get_redis()
        if client:
            key = f"spawn:rate:{subject}"
            try:
                count = client.incr(key)
                if count == 1:
                    client.expire(key, 60)
                if count > limit:
                    raise HTTPException(status_code=429, detail="rate limit exceeded")
                return
            except HTTPException:
                raise
            except Exception as exc:
                logger.warning("Redis rate limit failed: %s", exc)
                if self._redis_required:
                    raise HTTPException(status_code=503, detail="redis unavailable") from exc

        with self._lock:
            state = self._rate_cache.get(subject)
            if state is None or now >= state.reset_at:
                self._rate_cache[subject] = RateLimitState(1, now + 60)
                return
            state.count += 1
            if state.count > limit:
                raise HTTPException(status_code=429, detail="rate limit exceeded")

    def _purge_active(self, subject: str, now: float) -> None:
        entries = self._active_cache.get(subject)
        if not entries:
            return
        expired = [key for key, exp in entries.items() if exp <= now]
        for key in expired:
            entries.pop(key, None)

    def check_concurrent(
        self, subject: str, scenario_id: str, expires_at: datetime, limit: int
    ) -> None:
        if limit <= 0:
            return
        expires_ts = expires_at.timestamp()
        now = time.time()
        client = self._get_redis()
        if client:
            key = f"spawn:active:{subject}"
            try:
                client.zremrangebyscore(key, 0, now)
                existing = client.zscore(key, scenario_id)
                active_count = client.zcard(key)
                if existing is None and active_count >= limit:
                    raise HTTPException(
                        status_code=409, detail="concurrent scenario quota exceeded"
                    )
                client.zadd(key, {scenario_id: expires_ts})
                ttl = max(int(expires_ts - now), 1)
                client.expire(key, ttl)
                return
            except HTTPException:
                raise
            except Exception as exc:
                logger.warning("Redis quota check failed: %s", exc)
                if self._redis_required:
                    raise HTTPException(status_code=503, detail="redis unavailable") from exc

        with self._lock:
            self._purge_active(subject, now)
            entries = self._active_cache.setdefault(subject, {})
            if scenario_id not in entries and len(entries) >= limit:
                raise HTTPException(
                    status_code=409, detail="concurrent scenario quota exceeded"
                )
            entries[scenario_id] = expires_ts


spawn_limiter = SpawnLimiter()


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


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _timeout_config() -> tuple[float, float]:
    connect = float(os.getenv("HTTP_CONNECT_TIMEOUT_SECONDS", "2.0"))
    read = float(os.getenv("HTTP_READ_TIMEOUT_SECONDS", "5.0"))
    return connect, read


def _request_with_retries(
    method: str,
    url: str,
    *,
    json_body: dict | None = None,
    headers: dict | None = None,
    breaker: CircuitBreaker | None = None,
) -> requests.Response:
    if breaker and breaker.is_open():
        raise HTTPException(status_code=503, detail=f"{breaker.name} circuit breaker open")
    connect_timeout, read_timeout = _timeout_config()
    timeout = (connect_timeout, read_timeout)
    max_attempts = int(os.getenv("HTTP_MAX_RETRIES", "2")) + 1
    base_delay = float(os.getenv("HTTP_RETRY_BASE_DELAY_SECONDS", "0.2"))
    jitter = float(os.getenv("HTTP_RETRY_JITTER_SECONDS", "0.2"))

    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            response = requests.request(
                method, url, json=json_body, headers=headers, timeout=timeout
            )
            if response.status_code >= 500:
                raise requests.RequestException(f"upstream {response.status_code}")
            if breaker:
                breaker.record_success()
            return response
        except requests.RequestException as exc:
            last_exc = exc
            if breaker:
                breaker.record_failure()
            if attempt >= max_attempts - 1:
                break
            delay = base_delay + random.uniform(0, jitter)
            _sleep(delay)
    raise requests.RequestException("request failed") from last_exc


_opa_breaker = CircuitBreaker(
    "opa", float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))
)
_orchestrator_breaker = CircuitBreaker(
    "orchestrator", float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))
)
_egress_breaker = CircuitBreaker(
    "egress_gateway", float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "10"))
)


def load_template(track: str) -> dict:
    template_name = TRACK_TEMPLATE[track]
    template_path = TEMPLATE_DIR / template_name
    if not template_path.exists():
        raise HTTPException(status_code=500, detail="template not found")
    with template_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def opa_allows(template: dict) -> None:
    opa_url = os.getenv("OPA_URL")
    if not opa_url:
        if _forge_env() in {"dev", "development"}:
            return
        raise HTTPException(status_code=503, detail="OPA not configured")

    try:
        response = _request_with_retries(
            "POST",
            f"{opa_url}/v1/data/frostgate/forge/training/allow",
            json_body={"input": template},
            breaker=_opa_breaker,
        )
    except requests.RequestException as exc:
        logger.warning("OPA request failed: %s", exc)
        raise HTTPException(status_code=502, detail="OPA unavailable") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="OPA error")

    result = response.json().get("result")
    if result is not True:
        raise HTTPException(status_code=403, detail="OPA policy denied")


def record_billing(request_id: str, track: str) -> None:
    billing_mode = os.getenv("BILLING_MODE", "stub")
    logger.info("billing=%s request_id=%s track=%s", billing_mode, request_id, track)


def resolve_request_id(payload: SpawnRequest, request: Request) -> Optional[str]:
    header_name = os.getenv("REQUEST_ID_HEADER", "x-request-id")
    return payload.request_id or request.headers.get(header_name)


def resolve_subject_identifier(
    payload: SpawnRequest, request: Request, sat_claims: Optional[SatClaims]
) -> str:
    subject = payload.subject.strip() if payload.subject else ""
    if sat_claims:
        if subject and sat_claims.subject != subject:
            raise HTTPException(status_code=403, detail="subject mismatch")
        subject = sat_claims.subject
    if not subject:
        subject = request.headers.get(CLIENT_ID_HEADER, "").strip()
    if not subject:
        raise HTTPException(
            status_code=403,
            detail=f"subject identifier required (provide subject or {CLIENT_ID_HEADER})",
        )
    return subject


def resolve_tenant_identifier(
    request: Request, sat_claims: Optional[SatClaims], subject: str
) -> str:
    tenant_id = request.headers.get(TENANT_ID_HEADER, "").strip()
    if sat_claims:
        if tenant_id and sat_claims.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="tenant mismatch")
        tenant_id = sat_claims.tenant_id
    if not tenant_id:
        tenant_id = subject
    return tenant_id


def build_spawn_response(
    payload: SpawnRequest, request: Request, sat_claims: Optional[SatClaims]
) -> Tuple[SpawnResponse, EntitlementDecision]:
    request_id = resolve_request_id(payload, request)
    if not request_id:
        raise HTTPException(status_code=400, detail="request_id required")

    if payload.track not in TRACKS:
        raise HTTPException(status_code=400, detail="unsupported track")

    subject = resolve_subject_identifier(payload, request, sat_claims)
    tenant_id = resolve_tenant_identifier(request, sat_claims, subject)
    receipt_token = request.headers.get(ENTITLEMENT_RECEIPT_HEADER, "").strip() or None
    plan_override = request.headers.get("x-plan", "").strip()
    if plan_override:
        if os.getenv("DEV_ALLOW_XPLAN", "false").lower() != "true":
            raise HTTPException(status_code=403, detail="x-plan disabled")
        retention_days = int(os.getenv("DEV_XPLAN_RETENTION_DAYS", "30"))
        entitlement = EntitlementDecision(
            tier=normalize_tier(plan_override),
            retention_days=retention_days,
            source="x-plan",
        )
    else:
        entitlement = entitlement_resolver.resolve(
            subject=subject, tenant_id=tenant_id, receipt_token=receipt_token
        )

    if entitlement.source == "receipt" and entitlement.receipt_exp is not None:
        append_billing_audit_event(
            tenant_id=tenant_id,
            subject=subject,
            plan=entitlement.tier,
            receipt_exp=entitlement.receipt_exp,
        )

    et_token = mint_entitlement_token(
        subject=subject,
        tenant_id=tenant_id,
        plan=entitlement.tier,
        retention_days=entitlement.retention_days,
    )
    et_claims = verify_et(et_token)
    tier = normalize_tier(et_claims["plan"])
    entitlements = resolve_entitlements(tier)
    if payload.tier and normalize_tier(payload.tier) != tier:
        raise HTTPException(status_code=403, detail="tier mismatch")
    if sat_claims and normalize_tier(sat_claims.tier) != tier:
        raise HTTPException(status_code=403, detail="tier mismatch")
    if sat_claims and sat_claims.retention_days is not None:
        if sat_claims.retention_days != et_claims["retention_days"]:
            raise HTTPException(status_code=403, detail="retention mismatch")
    if payload.track not in entitlements.allowed_tracks:
        raise HTTPException(status_code=403, detail="track not allowed for tier")
    spawn_limiter.check_rate_limit(subject, entitlements.max_spawns_per_minute)

    if request_id in REQUEST_CACHE:
        cached = REQUEST_CACHE[request_id]
        cached_tier = cached.get("tier", tier)
        cached_retention = cached.get("retention_days", et_claims["retention_days"])
        cached_tenant = cached.get("tenant_id", tenant_id)
        if cached_tier != tier or cached_tenant != tenant_id:
            raise HTTPException(status_code=403, detail="entitlement mismatch")
        if cached_retention != et_claims["retention_days"]:
            raise HTTPException(status_code=403, detail="entitlement mismatch")
        issued_at = _sat_issued_at()
        sat_token = generate_sat(
            SatClaims(
                jti=str(uuid.uuid4()),
                exp=_sat_expiration(issued_at),
                iat=issued_at,
                track=cached["track"],
                template_id=cached["template_id"],
                subject=et_claims["subject"],
                tenant_id=et_claims["tenant_id"],
                tier=cached_tier,
                retention_days=et_claims["retention_days"],
                requested_limits=payload.requested_limits,
                scenario_id=cached["scenario_id"],
            )
        )
        return SpawnResponse(**cached, sat=sat_token), entitlement

    template = load_template(payload.track)
    opa_allows(template)
    record_billing(request_id, payload.track)

    scenario_id = payload.scenario_id or f"scn-{uuid.uuid4().hex[:12]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    base_url = os.getenv("SPAWN_BASE_URL", "http://localhost:8082")
    token_payload = AccessTokenPayload(
        scenario_id=scenario_id,
        request_id=request_id,
        track=payload.track,
        expires_at=expires_at,
    )
    access_token = generate_access_token(token_payload)
    access_url = f"{base_url}/v1/access/{scenario_id}?token={access_token}"
    issued_at = _sat_issued_at()
    sat_token = generate_sat(
        SatClaims(
            jti=str(uuid.uuid4()),
            exp=_sat_expiration(issued_at),
            iat=issued_at,
            track=payload.track,
            template_id=payload.template_id or payload.track,
            subject=et_claims["subject"],
            tenant_id=et_claims["tenant_id"],
            tier=tier,
            retention_days=et_claims["retention_days"],
            requested_limits=payload.requested_limits,
            scenario_id=scenario_id,
        )
    )

    response = SpawnResponse(
        request_id=request_id,
        scenario_id=scenario_id,
        access_url=access_url,
        access_token=access_token,
        expires_at=expires_at,
        sat=sat_token,
    )

    expires_at_dt = datetime.fromisoformat(expires_at)
    if expires_at_dt.tzinfo is None:
        expires_at_dt = expires_at_dt.replace(tzinfo=timezone.utc)
    spawn_limiter.check_concurrent(
        subject, scenario_id, expires_at_dt, entitlements.max_concurrent_scenarios
    )

    REQUEST_CACHE[request_id] = {
        "request_id": response.request_id,
        "scenario_id": response.scenario_id,
        "access_url": response.access_url,
        "access_token": response.access_token,
        "expires_at": response.expires_at,
        "track": payload.track,
        "template_id": payload.template_id or payload.track,
        "tier": tier,
        "retention_days": et_claims["retention_days"],
        "tenant_id": et_claims["tenant_id"],
    }

    return response, entitlement


def notify_orchestrator(
    payload: SpawnRequest, response: SpawnResponse, request: Request, tier: str
) -> None:
    orchestrator_url = os.getenv("ORCHESTRATOR_URL")
    if not orchestrator_url:
        return
    headers = {"x-request-id": request_id_ctx.get(), "x-sat": response.sat}
    body = {
        "scenario_id": response.scenario_id,
        "template": payload.track,
        "request_id": response.request_id,
        "tier": tier,
    }
    try:
        call = _request_with_retries(
            "POST",
            f"{orchestrator_url}/v1/scenarios",
            json_body=body,
            headers=headers,
            breaker=_orchestrator_breaker,
        )
    except requests.RequestException as exc:
        logger.warning("orchestrator request failed: %s", exc)
        raise HTTPException(status_code=502, detail="orchestrator unavailable") from exc
    if call.status_code >= 400:
        raise HTTPException(status_code=502, detail="orchestrator error")


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


def _check_egress_gateway() -> None:
    egress_url = os.getenv("EGRESS_GATEWAY_URL")
    if not egress_url:
        return
    expected = os.getenv("EGRESS_DRY_RUN_EXPECTED")
    if expected is None:
        forge_env = os.getenv("FORGE_ENV", "dev").lower()
        expected = "true" if forge_env == "dev" else "false"
    try:
        response = _request_with_retries(
            "GET", f"{egress_url}/readyz", breaker=_egress_breaker
        )
    except requests.RequestException as exc:
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


def _check_opa_ready() -> None:
    opa_url = os.getenv("OPA_URL")
    if not opa_url:
        if _forge_env() in {"dev", "development"}:
            return
        raise HTTPException(status_code=503, detail="opa not configured")
    try:
        response = _request_with_retries("GET", f"{opa_url}/health", breaker=_opa_breaker)
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail=f"opa unavailable: {exc}") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail=f"opa unhealthy: {response.status_code}")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "forge_spawn_service"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "forge_spawn_service"}


@app.get("/readyz")
def readyz() -> dict:
    _check_read_only_fs()
    _check_egress_gateway()
    _check_opa_ready()
    return {"status": "ready", "service": "forge_spawn_service"}


@app.post("/v1/spawn", response_model=SpawnResponse)
def spawn_scenario(payload: SpawnRequest, request: Request) -> SpawnResponse:
    sat_claims = enforce_spawn_authorization(request)
    response, entitlement = build_spawn_response(payload, request, sat_claims)
    notify_orchestrator(payload, response, request, entitlement.tier)
    return response


@app.post("/api/spawn", response_model=SpawnResponse)
def spawn_scenario_api(payload: SpawnRequest, request: Request) -> SpawnResponse:
    sat_claims = enforce_spawn_authorization(request)
    response, entitlement = build_spawn_response(payload, request, sat_claims)
    notify_orchestrator(payload, response, request, entitlement.tier)
    return response


@app.get("/v1/access/{scenario_id}")
def access_scenario(scenario_id: str, request: Request) -> dict:
    token = request.query_params.get("token") or request.headers.get("x-access-token")
    if not token:
        raise HTTPException(status_code=401, detail="token required")

    payload = verify_access_token(token)
    if payload.scenario_id != scenario_id:
        raise HTTPException(status_code=403, detail="token mismatch")

    return {
        "scenario_id": payload.scenario_id,
        "request_id": payload.request_id,
        "track": payload.track,
        "expires_at": payload.expires_at,
    }
