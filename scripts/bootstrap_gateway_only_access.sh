#!/usr/bin/env bash
set -euo pipefail

# Gateway-only access bootstrapper (Option C)
# Creates scaffolding + policies + tests + guardrails.
#
# Usage:
#   bash scripts/bootstrap_gateway_only_access.sh
#
# Assumptions:
# - Repo has: services/, policies/, scripts/
# - Python services use FastAPI (common in Foundry)
# - OPA is already in compose somewhere (forge_opa)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf "\n\033[1m%s\033[0m\n" "$*"; }
mkdirp() { mkdir -p "$1"; }
write_file() {
  local path="$1"
  shift
  mkdir -p "$(dirname "$path")"
  cat > "$path" <<'EOF'
'"$@"'
EOF
}

# More robust writer (keeps heredoc readable)
write() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
}

require_dirs() {
  for d in services policies scripts; do
    if [[ ! -d "$ROOT/$d" ]]; then
      echo "ERROR: expected directory $ROOT/$d to exist" >&2
      exit 1
    fi
  done
}

require_dirs

say "1) Adding OPA access policy + tests"

write "$ROOT/policies/access_gate.rego" <<'REGO'
package foundry.access

# Gateway-only access policy (Option C)
# Endpoints:
#   data.foundry.access.allow
#   data.foundry.access.deny_reasons

default allow := false

known_caps := {"web_tty"}

# Minimal, stable deny reasons. Keep these keys stable for ops + dashboards.
deny_reasons[r] {
  not cap_known
  r := "capability_unknown"
}

deny_reasons[r] {
  token_expired
  r := "token_expired"
}

deny_reasons[r] {
  tenant_blocked
  r := "tenant_blocked"
}

deny_reasons[r] {
  track_not_allowed
  r := "track_not_allowed"
}

# Allow only if no deny reasons exist.
allow {
  cap_known
  not token_expired
  not tenant_blocked
  not track_not_allowed
}

cap_known {
  known_caps[input.capability]
}

token_expired {
  # gateway passes token_exp as unix seconds
  input.token_exp <= time.now_ns() / 1000000000
}

tenant_blocked {
  # Example: tenant flag from upstream auth/billing system
  input.tenant_blocked == true
}

track_not_allowed {
  # Optional: enforce allowlist per tenant or per deployment
  input.track_allowlist_enabled == true
  not input.track_allowlist[input.track]
}
REGO

write "$ROOT/policies/access_gate_test.rego" <<'REGO'
package foundry.access_test

import data.foundry.access

test_allow_web_tty_happy_path {
  input := {
    "request_id": "req-1",
    "tenant_id": "t1",
    "subject": "u1",
    "scenario_id": "scn-abc",
    "track": "netplus",
    "capability": "web_tty",
    "source_ip": "1.2.3.4",
    "user_agent": "test",
    "token_exp": time.now_ns() / 1000000000 + 60,
    "tenant_blocked": false,
    "track_allowlist_enabled": false
  }
  access.allow with input as input
}

test_deny_unknown_cap {
  input := {
    "request_id": "req-2",
    "tenant_id": "t1",
    "subject": "u1",
    "scenario_id": "scn-abc",
    "track": "netplus",
    "capability": "ssh_root_lol",
    "source_ip": "1.2.3.4",
    "user_agent": "test",
    "token_exp": time.now_ns() / 1000000000 + 60,
    "tenant_blocked": false,
    "track_allowlist_enabled": false
  }
  not access.allow with input as input
  some r
  r := access.deny_reasons[_] with input as input
  r == "capability_unknown"
}

test_deny_expired_token {
  input := {
    "request_id": "req-3",
    "tenant_id": "t1",
    "subject": "u1",
    "scenario_id": "scn-abc",
    "track": "netplus",
    "capability": "web_tty",
    "source_ip": "1.2.3.4",
    "user_agent": "test",
    "token_exp": time.now_ns() / 1000000000 - 1,
    "tenant_blocked": false,
    "track_allowlist_enabled": false
  }
  not access.allow with input as input
}
REGO

say "2) Adding CI guardrail to forbid backup/editor files under policies/"

write "$ROOT/scripts/ci_guard_no_policy_backups.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

# OPA loads everything under policies/ by default.
# Backup/editor files can silently change policy behavior.
# This guardrail fails CI if any suspicious files exist.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bad="$(find "$ROOT/policies" -type f \( \
  -name "*~" -o -name "*.swp" -o -name "*.swo" -o -name "*.bak" -o -name "*.orig" -o -name "*.tmp" \
\) -print)"

if [[ -n "${bad}" ]]; then
  echo "ERROR: forbidden backup/editor files found under policies/:"
  echo "${bad}"
  exit 1
fi

echo "OK: no policy backup/editor files found."
SH
chmod +x "$ROOT/scripts/ci_guard_no_policy_backups.sh"

say "3) Adding egress gateway scaffold (FastAPI) with cap validation + OPA call + placeholder WS proxy"

mkdirp "$ROOT/services/egress_gateway/app"

write "$ROOT/services/egress_gateway/pyproject.toml" <<'TOML'
[project]
name = "egress_gateway"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "fastapi>=0.110",
  "uvicorn[standard]>=0.27",
  "httpx>=0.27",
  "pyjwt>=2.8",
  "redis>=5.0",
  "websockets>=12.0",
]

[tool.uvicorn]
factory = false
TOML

write "$ROOT/services/egress_gateway/app/main.py" <<'PY'
import hashlib
import os
import time
from typing import Any, Dict, Optional

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

try:
    import redis  # type: ignore
except Exception:
    redis = None

APP = FastAPI(title="forge_egress_gateway")

CAP_TOKEN_SECRET = os.environ.get("CAP_TOKEN_SECRET", "")
OPA_URL = os.environ.get("OPA_URL", "http://forge_opa:8181")
SAT_REQUIRED = os.environ.get("SAT_REQUIRED", "false").lower() == "true"

TTY_IDLE_SECONDS = int(os.environ.get("TTY_IDLE_SECONDS", "900"))
TTY_MAX_SECONDS = int(os.environ.get("TTY_MAX_SECONDS", "1800"))

REDIS_URL = os.environ.get("REDIS_URL", "")  # optional
CAP_SINGLE_USE = os.environ.get("CAP_SINGLE_USE", "false").lower() == "true"

KNOWN_CAPS = {"web_tty"}
AUD = "forge_egress_gateway"

rdb = None
if REDIS_URL and redis is not None:
    rdb = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def _token_hash(tok: str) -> str:
    return hashlib.sha256(tok.encode("utf-8")).hexdigest()

def _now() -> int:
    return int(time.time())

def _require_secret():
    if not CAP_TOKEN_SECRET:
        raise RuntimeError("CAP_TOKEN_SECRET is required")

def verify_cap_token(cap_token: str, scenario_id: str, capability: str) -> Dict[str, Any]:
    _require_secret()
    try:
        claims = jwt.decode(
            cap_token,
            CAP_TOKEN_SECRET,
            algorithms=["HS256"],
            audience=AUD,
            options={"require": ["exp", "iat", "aud", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="cap token expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"invalid cap token: {e}")

    if claims.get("scenario_id") != scenario_id:
        raise HTTPException(status_code=403, detail="scenario mismatch")
    if claims.get("cap") != capability:
        raise HTTPException(status_code=403, detail="capability mismatch")
    if capability not in KNOWN_CAPS:
        raise HTTPException(status_code=403, detail="capability unknown")

    return claims

def enforce_single_use(jti: str, exp: int):
    if not CAP_SINGLE_USE:
        return
    if rdb is None:
        raise HTTPException(status_code=500, detail="CAP_SINGLE_USE enabled but Redis not configured")

    key = f"cap:{jti}"
    ttl = max(1, exp - _now())
    # SETNX so first use wins
    ok = rdb.set(name=key, value="1", nx=True, ex=ttl)
    if not ok:
        raise HTTPException(status_code=401, detail="cap token already used")

async def opa_allow(input_doc: Dict[str, Any]) -> Dict[str, Any]:
    # POST /v1/data/foundry/access/allow
    async with httpx.AsyncClient(timeout=2.0) as client:
        resp = await client.post(f"{OPA_URL}/v1/data/foundry/access/allow", json={"input": input_doc})
        resp.raise_for_status()
        data = resp.json()
        # OPA returns {"result": true/false}
        return data

async def opa_deny_reasons(input_doc: Dict[str, Any]) -> Optional[list]:
    async with httpx.AsyncClient(timeout=2.0) as client:
        resp = await client.post(f"{OPA_URL}/v1/data/foundry/access/deny_reasons", json={"input": input_doc})
        if resp.status_code >= 400:
            return None
        data = resp.json()
        return data.get("result")

def require_sat(request: Request):
    if not SAT_REQUIRED:
        return
    # Placeholder: enforce your SAT here (header/cookie/assertion)
    sat = request.headers.get("X-SAT", "")
    if not sat:
        raise HTTPException(status_code=401, detail="SAT required")

def audit(event: str, fields: Dict[str, Any]):
    # Replace with your structured logger.
    # Never log raw tokens.
    print({"event": event, **fields})

@APP.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"

@APP.get("/v1/cap/web_tty/{sid}")
async def cap_web_tty(sid: str, request: Request, cap: str):
    # 1) SAT (optional)
    require_sat(request)

    # 2) Token validate (signature/aud/exp) + scenario binding
    claims = verify_cap_token(cap, scenario_id=sid, capability="web_tty")

    # 3) Optional single-use
    enforce_single_use(jti=str(claims["jti"]), exp=int(claims["exp"]))

    # 4) OPA allow
    input_doc = {
        "request_id": request.headers.get("X-Request-Id", str(claims.get("jti"))),
        "tenant_id": claims.get("tenant_id"),
        "subject": claims.get("sub"),
        "scenario_id": sid,
        "track": claims.get("track"),
        "capability": "web_tty",
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "token_exp": int(claims.get("exp", 0)),
        # optional flags you might pass from auth system
        "tenant_blocked": False,
        "track_allowlist_enabled": False,
        "track_allowlist": {},
    }

    allow_resp = await opa_allow(input_doc)
    allowed = bool(allow_resp.get("result"))

    if not allowed:
        deny = await opa_deny_reasons(input_doc)
        audit("access.capability_denied", {
            "scenario_id": sid,
            "subject": claims.get("sub"),
            "tenant_id": claims.get("tenant_id"),
            "capability": "web_tty",
            "jti": claims.get("jti"),
            "deny_reasons": deny,
        })
        raise HTTPException(status_code=403, detail={"deny_reasons": deny})

    audit("access.session_started", {
        "scenario_id": sid,
        "subject": claims.get("sub"),
        "tenant_id": claims.get("tenant_id"),
        "capability": "web_tty",
        "jti": claims.get("jti"),
        "cap_hash": _token_hash(cap),
    })

    # 5) WS proxy to ttyd
    #
    # This endpoint is currently HTTP GET.
    # To actually proxy the ttyd websocket, you’ll implement a proper WebSocket route:
    #   @APP.websocket("/v1/cap/web_tty/{sid}/ws")
    # and then connect to:
    #   ws://ttyd:7681/ws  (resolved inside scenario network)
    #
    # For now we return a clear placeholder.
    return {
        "status": "ok",
        "note": "WS proxy not implemented in scaffold. Add FastAPI WebSocket route and proxy frames to ttyd.",
        "timeouts": {"idle": TTY_IDLE_SECONDS, "max": TTY_MAX_SECONDS},
        "audit": "access.session_started emitted",
    }
PY

write "$ROOT/services/egress_gateway/Dockerfile" <<'DOCKER'
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir -U pip \
  && pip install --no-cache-dir .

COPY app /app/app

EXPOSE 8080
CMD ["uvicorn", "app.main:APP", "--host", "0.0.0.0", "--port", "8080"]
DOCKER

say "4) Adding spawn_service capability token helper scaffold"

mkdirp "$ROOT/services/spawn_service/app"

write "$ROOT/services/spawn_service/app/capabilities.py" <<'PY'
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
PY

say "5) Adding .env.example knobs (append if file exists)"

ENV_EXAMPLE="$ROOT/.env.example"
touch "$ENV_EXAMPLE"
append_if_missing() {
  local line="$1"
  grep -qF "$line" "$ENV_EXAMPLE" || echo "$line" >> "$ENV_EXAMPLE"
}

append_if_missing ""
append_if_missing "# --- Gateway-only access (Option C) ---"
append_if_missing "EGRESS_GATEWAY_PUBLIC_URL=https://gateway.example.com"
append_if_missing "CAP_TOKEN_SECRET=change-me-long-random"
append_if_missing "CAP_TOKEN_TTL_SECONDS=300"
append_if_missing "OPA_URL=http://forge_opa:8181"
append_if_missing "TTY_IDLE_SECONDS=900"
append_if_missing "TTY_MAX_SECONDS=1800"
append_if_missing "SAT_REQUIRED=false"
append_if_missing "CAP_SINGLE_USE=false"
append_if_missing "REDIS_URL=redis://forge_redis:6379/0"

say "6) Adding smoke script (happy-path + deny-path hooks)"

write "$ROOT/scripts/smoke_gateway_only_access.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

# Minimal smoke test for Option C.
# Assumes spawn_service exposes /v1/access/{sid} and returns capabilities with URL.
#
# Usage:
#   SPAWN_URL=http://localhost:8082  SID=scn-abc ACCESS_TOKEN=... bash scripts/smoke_gateway_only_access.sh

SPAWN_URL="${SPAWN_URL:-http://localhost:8082}"
SID="${SID:?set SID=scn-...}"
ACCESS_TOKEN="${ACCESS_TOKEN:-}"

hdrs=()
if [[ -n "$ACCESS_TOKEN" ]]; then
  hdrs=(-H "X-Access-Token: $ACCESS_TOKEN")
fi

echo "[1] Fetch capabilities"
resp="$(curl -sS "${hdrs[@]}" "$SPAWN_URL/v1/access/$SID")"
echo "$resp" | jq .

cap_url="$(echo "$resp" | jq -r '.capabilities[] | select(.kind=="web_tty") | .url' | head -n1)"
if [[ -z "$cap_url" || "$cap_url" == "null" ]]; then
  echo "ERROR: no web_tty capability url returned"
  exit 1
fi

echo "[2] Hit gateway cap URL (HTTP placeholder response expected in scaffold)"
curl -sS "$cap_url" | jq .

echo "[3] NOTE: This scaffold does not implement WS proxy yet."
echo "    Once WS exists, you can add: websocat or wscat to validate interactive session."
SH
chmod +x "$ROOT/scripts/smoke_gateway_only_access.sh"

say "7) Done. Next actions you actually need to do (because humans love unfinished work):"
cat <<'NEXT'
- Wire spawn_service route GET /v1/access/{sid} to use services/spawn_service/app/capabilities.py
- Add egress_gateway service to compose with CAP_TOKEN_SECRET + OPA_URL
- Implement the actual WebSocket proxy route in egress_gateway (FastAPI websocket)
- Orchestrator: launch ttyd container on scenario network + attach gateway to scenario network
- Run OPA tests: opa test -v policies/
- Run guardrail: scripts/ci_guard_no_policy_backups.sh
- Run smoke: scripts/smoke_gateway_only_access.sh
NEXT
