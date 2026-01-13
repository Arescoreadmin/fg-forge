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


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


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
    issued_at: int
    expires_at: int
    iat: int
    exp: int
    jti: str


@dataclass(frozen=True)
class EntitlementDecision:
    tier: str
    retention_days: int
    source: str
    receipt_exp: Optional[int] = None


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

        return EntitlementDecision(
            tier=plan,
            retention_days=claims.retention_days,
            source="receipt",
            receipt_exp=claims.exp,
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


def mint_et(claims: dict) -> str:
    if not isinstance(claims, dict):
        raise HTTPException(status_code=400, detail="invalid entitlement claims")
    payload = dict(claims)
    issued_at = payload.get("issued_at")
    expires_at = payload.get("expires_at")
    if issued_at is None:
        issued_at = _et_issued_at()
        payload["issued_at"] = issued_at
    if expires_at is None:
        expires_at = _et_expiration(int(issued_at))
        payload["expires_at"] = expires_at
    if "iat" not in payload:
        payload["iat"] = payload["issued_at"]
    if "exp" not in payload:
        payload["exp"] = payload["expires_at"]
    payload_bytes = _canonical_json(payload)
    signature = hmac.new(
        _get_et_secret().encode("utf-8"), payload_bytes, "sha256"
    ).digest()
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"


def verify_et(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="invalid entitlement token")
    payload_encoded, signature_encoded = parts

    try:
        payload_bytes = _b64url_decode(payload_encoded)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="invalid entitlement token") from exc

    expected_signature = hmac.new(
        _get_et_secret().encode("utf-8"), payload_bytes, "sha256"
    ).digest()
    expected_encoded = _b64url_encode(expected_signature)
    if not hmac.compare_digest(expected_encoded, signature_encoded):
        raise HTTPException(status_code=401, detail="invalid entitlement token")

    try:
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="invalid entitlement token") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail="invalid entitlement token")

    required = {
        "subject",
        "tenant_id",
        "plan",
        "retention_days",
        "issued_at",
        "expires_at",
        "iat",
        "exp",
        "jti",
    }
    missing = [key for key in required if key not in payload]
    if missing:
        raise HTTPException(status_code=401, detail="invalid entitlement token")

    try:
        issued_at = int(payload["issued_at"])
        expires_at = int(payload["expires_at"])
        iat = int(payload["iat"])
        exp = int(payload["exp"])
        retention_days = int(payload["retention_days"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid entitlement token") from exc

    if issued_at > expires_at or iat > exp:
        raise HTTPException(status_code=401, detail="invalid entitlement token")
    if issued_at != iat or expires_at != exp:
        raise HTTPException(status_code=401, detail="invalid entitlement token")

    now = int(datetime.now(timezone.utc).timestamp())
    if expires_at < now or exp < now:
        raise HTTPException(status_code=401, detail="entitlement token expired")

    normalize_tier(str(payload["plan"]))
    if retention_days < 0:
        raise HTTPException(status_code=401, detail="invalid entitlement token")

    return payload


def mint_entitlement_token(
    *,
    subject: str,
    tenant_id: str,
    plan: str,
    retention_days: int,
) -> str:
    issued_at = _et_issued_at()
    expires_at = _et_expiration(issued_at)
    claims = {
        "subject": subject,
        "tenant_id": tenant_id,
        "plan": normalize_tier(plan),
        "retention_days": retention_days,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "iat": issued_at,
        "exp": expires_at,
        "jti": str(uuid.uuid4()),
    }
    return mint_et(claims)


def verify_entitlement_token(token: str) -> EntitlementTokenClaims:
    payload = verify_et(token)
    try:
        return EntitlementTokenClaims.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=401, detail="invalid entitlement token") from exc


def _forge_env() -> str:
    return os.getenv("FORGE_ENV", "dev").lower()


def _billing_audit_dir() -> str:
    return os.getenv("BILLING_AUDIT_DIR", "storage/tenants")


def _billing_audit_path(tenant_id: str) -> str:
    return str(Path(_billing_audit_dir()) / tenant_id / "billing_audit.jsonl")


def _audit_entry_hash(prev_hash: str, data: dict[str, Any]) -> str:
    payload = prev_hash.encode("utf-8") + _canonical_json(data)
    return hashlib.sha256(payload).hexdigest()


def append_audit_entry(chain: list[dict], entry: dict) -> list[dict]:
    prev_hash = chain[-1].get("hash", "") if chain else ""
    data = dict(entry)
    entry_hash = _audit_entry_hash(prev_hash, data)
    new_entry = {"data": data, "prev_hash": prev_hash, "hash": entry_hash}
    return [*chain, new_entry]


def verify_audit_chain(chain: list[dict]) -> bool:
    prev_hash = ""
    for entry in chain:
        if not isinstance(entry, dict):
            return False
        data = entry.get("data")
        entry_hash = entry.get("hash")
        expected_prev = entry.get("prev_hash")
        if expected_prev != prev_hash:
            return False
        if not isinstance(data, dict) or not isinstance(entry_hash, str):
            return False
        expected_hash = _audit_entry_hash(prev_hash, data)
        if not hmac.compare_digest(entry_hash, expected_hash):
            return False
        prev_hash = entry_hash
    return True


def append_billing_audit_event(
    *,
    tenant_id: str,
    subject: str,
    plan: str,
    receipt_exp: int,
) -> None:
    audit_path = Path(_billing_audit_path(tenant_id))
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        if _forge_env() in {"dev", "development"}:
            logger.warning("Billing audit chain skipped: %s", exc)
            return
        raise HTTPException(
            status_code=500, detail="billing audit chain unavailable"
        ) from exc

    chain: list[dict] = []
    if audit_path.exists():
        try:
            with audit_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        chain.append(json.loads(line))
        except (OSError, json.JSONDecodeError) as exc:
            if _forge_env() in {"dev", "development"}:
                logger.warning("Billing audit chain skipped: %s", exc)
                return
            raise HTTPException(
                status_code=500, detail="billing audit chain invalid"
            ) from exc
        if not verify_audit_chain(chain):
            if _forge_env() in {"dev", "development"}:
                logger.warning("Billing audit chain skipped: invalid chain")
                return
            raise HTTPException(
                status_code=500, detail="billing audit chain invalid"
            )
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "subject": subject,
        "plan": normalize_tier(plan),
        "receipt_exp": receipt_exp,
    }
    new_entry = append_audit_entry(chain, entry)[-1]
    try:
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(new_entry, ensure_ascii=False))
            handle.write("\n")
    except OSError as exc:
        if _forge_env() in {"dev", "development"}:
            logger.warning("Billing audit chain skipped: %s", exc)
            return
        raise HTTPException(
            status_code=500, detail="billing audit chain unavailable"
        ) from exc


def verify_billing_audit_chain(path: Path) -> bool:
    chain: list[dict] = []
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
                chain.append(entry)
    except OSError:
        return False
    return verify_audit_chain(chain)
