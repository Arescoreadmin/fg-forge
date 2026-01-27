import os
import time
import uuid
from typing import Dict, Any

import jwt

CAP_TOKEN_SECRET = os.environ.get("CAP_TOKEN_SECRET", "")
CAP_TOKEN_TTL_SECONDS = int(os.environ.get("CAP_TOKEN_TTL_SECONDS", "300"))
EGRESS_GATEWAY_PUBLIC_URL = os.environ.get("EGRESS_GATEWAY_PUBLIC_URL", "")

AUD = "forge_egress_gateway"

def _require_env():
    if not CAP_TOKEN_SECRET:
        raise RuntimeError("CAP_TOKEN_SECRET is required")
    if not EGRESS_GATEWAY_PUBLIC_URL:
        raise RuntimeError("EGRESS_GATEWAY_PUBLIC_URL is required")

def mint_cap_token(*, subject: str, tenant_id: str, scenario_id: str, track: str, cap: str) -> str:
    _require_env()
    now = int(time.time())
    jti = str(uuid.uuid4())
    claims: Dict[str, Any] = {
        "jti": jti,
        "sub": subject,
        "tenant_id": tenant_id,
        "scenario_id": scenario_id,
        "track": track,
        "cap": cap,
        "aud": AUD,
        "iat": now,
        "exp": now + CAP_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(claims, CAP_TOKEN_SECRET, algorithm="HS256")

def capability_url(*, scenario_id: str, cap: str, cap_token: str) -> str:
    _require_env()
    # Gateway endpoint per your contract:
    # GET /v1/cap/web_tty/{sid}?cap=<cap_token>
    return f"{EGRESS_GATEWAY_PUBLIC_URL}/v1/cap/{cap}/{scenario_id}?cap={cap_token}"
