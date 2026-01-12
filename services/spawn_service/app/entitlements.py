from __future__ import annotations

import base64
import hmac
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
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

        return EntitlementDecision(
            tier=normalize_tier(claims.tier),
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
