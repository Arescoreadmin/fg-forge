from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger("forge_spawn_service.entitlements")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def normalize_tier(value: str) -> str:
    tier = (value or "").strip().upper()
    if not tier:
        raise HTTPException(status_code=403, detail="tier required")
    return tier


class ReceiptClaims(BaseModel):
    tenant_id: str
    tier: str
    retention_days: int = Field(..., ge=0)
    exp: int
    subject: Optional[str] = None


class EntitlementTokenClaims(BaseModel):
    subject: str
    tenant_id: str
    plan: str
    retention_days: int = Field(..., ge=0)
    exp: int
    iat: int
    jti: str


@dataclass(frozen=True)
class EntitlementDecision:
    tier: str
    retention_days: int
    source: str


class EntitlementResolver:
    def __init__(
        self,
        *,
        redis_url: str | None = None,
        redis_hash: str | None = None,
        file_path: str | None = None,
    ) -> None:
        self._redis_url = redis_url or os.getenv("ENTITLEMENTS_REDIS_URL")
        self._redis_hash = redis_hash or os.getenv(
            "ENTITLEMENTS_REDIS_HASH", "entitlements"
        )
        self._file_path = file_path or os.getenv("ENTITLEMENTS_FILE")
        self._redis_client = None

    def resolve(
        self,
        *,
        subject: str,
        tenant_id: str,
        receipt_token: str | None = None,
    ) -> EntitlementDecision:
        if receipt_token:
            decision = self._resolve_from_receipt(
                receipt_token, tenant_id=tenant_id, subject=subject
            )
            if decision:
                return decision

        decision = self._resolve_from_store(tenant_id=tenant_id)
        if decision:
            return decision

        if os.getenv("ALLOW_FREE_DEFAULT", "false").lower() == "true":
            retention_days = int(os.getenv("FREE_DEFAULT_RETENTION_DAYS", "30"))
            return EntitlementDecision(
                tier="FREE",
                retention_days=retention_days,
                source="free-default",
            )

        raise HTTPException(status_code=403, detail="entitlement not found")

    def _resolve_from_receipt(
        self, token: str, *, tenant_id: str, subject: str
    ) -> Optional[EntitlementDecision]:
        secret = os.getenv("RECEIPT_HMAC_SECRET")
        if not secret:
            raise HTTPException(
                status_code=500, detail="receipt verification not configured"
            )
        try:
            payload_encoded, signature_encoded = token.split(".", 1)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="invalid receipt") from exc

        expected_signature = hmac.new(
            secret.encode("utf-8"), payload_encoded.encode("utf-8"), "sha256"
        ).digest()
        expected_encoded = _b64url_encode(expected_signature)
        if not hmac.compare_digest(expected_encoded, signature_encoded):
            raise HTTPException(status_code=401, detail="invalid receipt")

        try:
            payload = json.loads(_b64url_decode(payload_encoded))
            claims = ReceiptClaims.model_validate(payload)
        except (json.JSONDecodeError, ValidationError) as exc:
            raise HTTPException(status_code=401, detail="invalid receipt") from exc

        now = int(datetime.now(timezone.utc).timestamp())
        if claims.exp < now:
            raise HTTPException(status_code=401, detail="receipt expired")
        if claims.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="receipt tenant mismatch")
        if claims.subject and claims.subject != subject:
            raise HTTPException(status_code=403, detail="receipt subject mismatch")

        plan = normalize_tier(claims.tier)
        append_billing_audit_event(
            tenant_id=tenant_id,
            subject=subject,
            plan=plan,
            receipt_exp=claims.exp,
        )

        return EntitlementDecision(
            tier=plan,
            retention_days=claims.retention_days,
            source="receipt",
        )

    def _resolve_from_store(self, *, tenant_id: str) -> Optional[EntitlementDecision]:
        if self._redis_url:
            record = self._read_from_redis(tenant_id)
            if record:
                return self._decision_from_record(record, source="redis")
        if self._file_path:
            record = self._read_from_file(tenant_id)
            if record:
                return self._decision_from_record(record, source="file")
        return None

    def _read_from_redis(self, tenant_id: str) -> Optional[dict[str, Any]]:
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
                logger.warning("Entitlements redis init failed: %s", exc)
                raise HTTPException(
                    status_code=503, detail="entitlements store unavailable"
                ) from exc
        try:
            data = self._redis_client.hget(self._redis_hash, tenant_id)
        except Exception as exc:
            logger.warning("Entitlements redis read failed: %s", exc)
            raise HTTPException(
                status_code=503, detail="entitlements store unavailable"
            ) from exc
        if not data:
            return None
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            logger.warning("Entitlements redis payload invalid")
            raise HTTPException(
                status_code=503, detail="entitlements store invalid"
            ) from exc
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=503, detail="entitlements store invalid")
        return parsed

    def _read_from_file(self, tenant_id: str) -> Optional[dict[str, Any]]:
        try:
            with open(self._file_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError as exc:
            logger.warning("Entitlements file missing")
            raise HTTPException(
                status_code=503, detail="entitlements store unavailable"
            ) from exc
        except json.JSONDecodeError as exc:
            logger.warning("Entitlements file invalid")
            raise HTTPException(
                status_code=503, detail="entitlements store invalid"
            ) from exc

        if not isinstance(payload, dict):
            raise HTTPException(status_code=503, detail="entitlements store invalid")

        record = payload.get(tenant_id)
        if record is None:
            return None
        if not isinstance(record, dict):
            raise HTTPException(status_code=503, detail="entitlements store invalid")
        return record

    def _decision_from_record(
        self, record: dict[str, Any], *, source: str
    ) -> EntitlementDecision:
        try:
            tier = normalize_tier(str(record["tier"]))
            retention_days = int(record["retention_days"])
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=503, detail="entitlements store invalid") from exc
        return EntitlementDecision(
            tier=tier, retention_days=retention_days, source=source
        )


_et_secret_cache: Optional[str] = None
_et_secret_warning_emitted = False


def _get_et_secret() -> str:
    global _et_secret_cache, _et_secret_warning_emitted
    if _et_secret_cache:
        return _et_secret_cache
    secret = os.getenv("ET_HMAC_SECRET")
    if secret:
        _et_secret_cache = secret
        return secret
    if os.getenv("DEV_ALLOW_MISSING_ET_SECRET", "false").lower() == "true":
        secret = uuid.uuid4().hex
        _et_secret_cache = secret
        if not _et_secret_warning_emitted:
            logger.warning("ET_HMAC_SECRET not set; using ephemeral dev secret")
            _et_secret_warning_emitted = True
        return secret
    raise HTTPException(status_code=500, detail="ET secret not configured")


def _et_issued_at() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _et_expiration(issued_at: int) -> int:
    ttl_seconds = int(os.getenv("ET_TTL_SECONDS", "300"))
    return issued_at + ttl_seconds


def mint_entitlement_token(
    *,
    subject: str,
    tenant_id: str,
    plan: str,
    retention_days: int,
) -> str:
    issued_at = _et_issued_at()
    claims = EntitlementTokenClaims(
        subject=subject,
        tenant_id=tenant_id,
        plan=normalize_tier(plan),
        retention_days=retention_days,
        exp=_et_expiration(issued_at),
        iat=issued_at,
        jti=str(uuid.uuid4()),
    )
    header = {"alg": "HS256", "typ": "ET"}
    header_encoded = _b64url_encode(json.dumps(header).encode("utf-8"))
    payload_encoded = _b64url_encode(claims.model_dump_json().encode("utf-8"))
    signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
    signature = hmac.new(_get_et_secret().encode("utf-8"), signing_input, "sha256").digest()
    signature_encoded = _b64url_encode(signature)
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_entitlement_token(token: str) -> EntitlementTokenClaims:
    try:
        header_encoded, payload_encoded, signature_encoded = token.split(".", 2)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid entitlement token") from exc

    signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
    expected_signature = hmac.new(
        _get_et_secret().encode("utf-8"), signing_input, "sha256"
    ).digest()
    expected_encoded = _b64url_encode(expected_signature)
    if not hmac.compare_digest(expected_encoded, signature_encoded):
        raise HTTPException(status_code=401, detail="invalid entitlement token")

    try:
        header = json.loads(_b64url_decode(header_encoded))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid entitlement token") from exc
    if header.get("alg") != "HS256" or header.get("typ") != "ET":
        raise HTTPException(status_code=401, detail="invalid entitlement token")

    try:
        payload = EntitlementTokenClaims.model_validate(
            json.loads(_b64url_decode(payload_encoded))
        )
    except (json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=401, detail="invalid entitlement token") from exc

    now = int(datetime.now(timezone.utc).timestamp())
    if payload.iat > payload.exp:
        raise HTTPException(status_code=401, detail="invalid entitlement token")
    if payload.exp < now:
        raise HTTPException(status_code=401, detail="entitlement token expired")
    normalize_tier(payload.plan)
    return payload


def _billing_audit_dir() -> str:
    return os.getenv("BILLING_AUDIT_DIR", "storage/tenants")


def _billing_audit_path(tenant_id: str) -> str:
    return str(Path(_billing_audit_dir()) / tenant_id / "billing_audit.jsonl")


def _audit_entry_hash(entry: dict[str, Any]) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def append_billing_audit_event(
    *,
    tenant_id: str,
    subject: str,
    plan: str,
    receipt_exp: int,
) -> None:
    audit_path = Path(_billing_audit_path(tenant_id))
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = ""
    if audit_path.exists():
        try:
            with audit_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        prev_hash = json.loads(line).get("entry_hash", "")
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=500, detail="billing audit chain invalid"
            ) from exc
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "subject": subject,
        "plan": normalize_tier(plan),
        "receipt_exp": receipt_exp,
        "prev_hash": prev_hash,
    }
    entry_hash = _audit_entry_hash(entry)
    entry["entry_hash"] = entry_hash
    try:
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry))
            handle.write("\n")
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail="billing audit chain unavailable"
        ) from exc


def verify_billing_audit_chain(path: Path) -> bool:
    prev_hash = ""
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False
                entry_hash = entry.get("entry_hash", "")
                expected_prev = entry.get("prev_hash", "")
                if expected_prev != prev_hash:
                    return False
                payload = {
                    "ts": entry.get("ts"),
                    "tenant_id": entry.get("tenant_id"),
                    "subject": entry.get("subject"),
                    "plan": entry.get("plan"),
                    "receipt_exp": entry.get("receipt_exp"),
                    "prev_hash": entry.get("prev_hash"),
                }
                expected_hash = _audit_entry_hash(payload)
                if not hmac.compare_digest(entry_hash, expected_hash):
                    return False
                prev_hash = entry_hash
    except OSError:
        return False
    return True
