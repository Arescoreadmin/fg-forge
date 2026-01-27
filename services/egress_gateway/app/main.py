import asyncio
import hashlib
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse

try:
    import redis  # type: ignore
except Exception:
    redis = None

try:
    import websockets  # type: ignore
except Exception:
    websockets = None


APP = FastAPI(title="forge_egress_gateway")

# -------------------------
# Config
# -------------------------
CAP_TOKEN_SECRET = os.environ.get("CAP_TOKEN_SECRET", "")
OPA_URL = os.environ.get("OPA_URL", "http://forge_opa:8181")
SAT_REQUIRED = os.environ.get("SAT_REQUIRED", "false").lower() == "true"

# Session enforcement
TTY_IDLE_SECONDS = int(os.environ.get("TTY_IDLE_SECONDS", "900"))
TTY_MAX_SECONDS = int(os.environ.get("TTY_MAX_SECONDS", "1800"))

# Optional Redis (single-use + future rate limiting)
REDIS_URL = os.environ.get("REDIS_URL", "")
CAP_SINGLE_USE = os.environ.get("CAP_SINGLE_USE", "false").lower() == "true"

# ttyd upstream (must be resolvable from within scenario network)
TTYD_HOST = os.environ.get("TTYD_HOST", "ttyd")
TTYD_PORT = int(os.environ.get("TTYD_PORT", "7681"))
TTYD_SCHEME = os.environ.get("TTYD_SCHEME", "http")  # inside docker networks
TTYD_WS_SCHEME = os.environ.get("TTYD_WS_SCHEME", "ws")

# Networking/timeouts
OPA_TIMEOUT_SECONDS = float(os.environ.get("OPA_TIMEOUT_SECONDS", "2.0"))
UPSTREAM_HTTP_TIMEOUT_SECONDS = float(os.environ.get("UPSTREAM_HTTP_TIMEOUT_SECONDS", "30.0"))

# Limits
WS_MAX_MESSAGE_BYTES = int(os.environ.get("WS_MAX_MESSAGE_BYTES", str(2**20)))  # 1 MiB default

KNOWN_CAPS = {"web_tty"}
AUD = "forge_egress_gateway"

rdb = None
if REDIS_URL and redis is not None:
    rdb = redis.Redis.from_url(REDIS_URL, decode_responses=True)


# -------------------------
# Helpers
# -------------------------
def _token_hash(tok: str) -> str:
    return hashlib.sha256(tok.encode("utf-8")).hexdigest()


def _now() -> int:
    return int(time.time())


def _require_secret() -> None:
    if not CAP_TOKEN_SECRET:
        raise RuntimeError("CAP_TOKEN_SECRET is required")


def _client_ip(request: Request) -> Optional[str]:
    # Honor common proxy headers (you should lock this down at ingress if exposed publicly)
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # left-most is original
        return xff.split(",")[0].strip() or None
    xrip = request.headers.get("x-real-ip", "")
    if xrip:
        return xrip.strip() or None
    return request.client.host if request.client else None


def _require_websockets() -> None:
    if websockets is None:
        raise RuntimeError("websockets package missing (check services/egress_gateway/pyproject.toml)")


def verify_cap_token(cap_token: str, scenario_id: str, capability: str) -> Dict[str, Any]:
    _require_secret()
    if capability not in KNOWN_CAPS:
        raise HTTPException(status_code=403, detail="capability unknown")

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
    except Exception:
        raise HTTPException(status_code=401, detail="invalid cap token")

    if claims.get("scenario_id") != scenario_id:
        raise HTTPException(status_code=403, detail="scenario mismatch")
    if claims.get("cap") != capability:
        raise HTTPException(status_code=403, detail="capability mismatch")

    return claims


def enforce_single_use(jti: str, exp: int) -> None:
    if not CAP_SINGLE_USE:
        return
    if rdb is None:
        raise HTTPException(status_code=500, detail="CAP_SINGLE_USE enabled but Redis not configured")

    key = f"cap:{jti}"
    ttl = max(1, exp - _now())
    ok = rdb.set(name=key, value="1", nx=True, ex=ttl)
    if not ok:
        raise HTTPException(status_code=401, detail="cap token already used")


def require_sat(request: Request) -> None:
    if not SAT_REQUIRED:
        return
    # Placeholder SAT enforcement. Replace with your real SAT verifier.
    sat = request.headers.get("X-SAT", "")
    if not sat:
        raise HTTPException(status_code=401, detail="SAT required")


def audit(event: str, fields: Dict[str, Any]) -> None:
    # Swap this for structured logging (JSON logger). Never log raw tokens.
    # Keeping it stdout JSON-ish for now.
    safe = dict(fields)
    print({"event": event, **safe})


async def opa_allow(input_doc: Dict[str, Any]) -> bool:
    async with httpx.AsyncClient(timeout=OPA_TIMEOUT_SECONDS) as client:
        resp = await client.post(f"{OPA_URL}/v1/data/foundry/access/allow", json={"input": input_doc})
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get("result"))


async def opa_deny_reasons(input_doc: Dict[str, Any]) -> List[str]:
    async with httpx.AsyncClient(timeout=OPA_TIMEOUT_SECONDS) as client:
        resp = await client.post(f"{OPA_URL}/v1/data/foundry/access/deny_reasons", json={"input": input_doc})
        if resp.status_code >= 400:
            return []
        data = resp.json()
        out = data.get("result")
        return out if isinstance(out, list) else []


def _opa_input(*, request: Request, claims: Dict[str, Any], sid: str, capability: str) -> Dict[str, Any]:
    return {
        "request_id": request.headers.get("X-Request-Id", str(claims.get("jti"))),
        "tenant_id": claims.get("tenant_id"),
        "subject": claims.get("sub"),
        "scenario_id": sid,
        "track": claims.get("track"),
        "capability": capability,
        "source_ip": _client_ip(request),
        "user_agent": request.headers.get("user-agent"),
        "token_exp": int(claims.get("exp", 0)),
        # Optional flags (wire real values when you have them)
        "tenant_blocked": False,
        "track_allowlist_enabled": False,
        "track_allowlist": {},
    }


def _strip_hop_by_hop_headers(headers: Dict[str, str]) -> Dict[str, str]:
    hop = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
    return {k: v for k, v in headers.items() if k.lower() not in hop}


def _upstream_base(sid: str) -> str:
    # ttyd should be started with base-path: /v1/cap/web_tty/<sid>
    return f"{TTYD_SCHEME}://{TTYD_HOST}:{TTYD_PORT}/v1/cap/web_tty/{sid}"


def _upstream_ws(sid: str) -> str:
    # ttyd websocket under base-path is typically /ws
    return f"{TTYD_WS_SCHEME}://{TTYD_HOST}:{TTYD_PORT}/v1/cap/web_tty/{sid}/ws"


async def _authorize_or_403(*, request: Request, sid: str, cap: str, capability: str) -> Dict[str, Any]:
    require_sat(request)

    claims = verify_cap_token(cap, scenario_id=sid, capability=capability)
    enforce_single_use(jti=str(claims["jti"]), exp=int(claims["exp"]))

    input_doc = _opa_input(request=request, claims=claims, sid=sid, capability=capability)

    allowed = await opa_allow(input_doc)
    if not allowed:
        deny = await opa_deny_reasons(input_doc)
        audit(
            "access.capability_denied",
            {
                "scenario_id": sid,
                "subject": claims.get("sub"),
                "tenant_id": claims.get("tenant_id"),
                "capability": capability,
                "jti": claims.get("jti"),
                "deny_reasons": deny,
                "cap_hash": _token_hash(cap),
            },
        )
        raise HTTPException(status_code=403, detail={"deny_reasons": deny})

    return claims


# -------------------------
# Health
# -------------------------
@APP.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@APP.get("/readyz", response_class=PlainTextResponse)
async def readyz() -> str:
    # Basic dependency readiness: OPA reachable (optional but useful)
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            r = await client.get(f"{OPA_URL}/health")
            if r.status_code >= 400:
                raise RuntimeError("OPA unhealthy")
    except Exception:
        raise HTTPException(status_code=503, detail="not ready")
    return "ok"


# -------------------------
# web_tty capability: HTTP proxy
# -------------------------
@APP.api_route(
    "/v1/cap/web_tty/{sid}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@APP.api_route(
    "/v1/cap/web_tty/{sid}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def cap_web_tty_http(sid: str, request: Request, cap: str, path: str = "") -> Response:
    claims = await _authorize_or_403(request=request, sid=sid, cap=cap, capability="web_tty")

    audit(
        "access.session_http",
        {
            "scenario_id": sid,
            "subject": claims.get("sub"),
            "tenant_id": claims.get("tenant_id"),
            "capability": "web_tty",
            "jti": claims.get("jti"),
            "cap_hash": _token_hash(cap),
            "path": f"/{path}" if path else "/",
            "method": request.method,
        },
    )

    upstream_base = _upstream_base(sid)
    url = f"{upstream_base}/{path}" if path else upstream_base

    # Forward query params, but do NOT forward cap token to upstream unless ttyd needs it.
    # ttyd does not need the cap, gateway enforces it. We strip `cap` when sending upstream.
    params = dict(request.query_params)
    params.pop("cap", None)

    headers = dict(request.headers)
    headers.pop("host", None)
    # Defensive: strip auth-ish headers you don't want reaching ttyd
    headers.pop("authorization", None)

    body = await request.body()

    async with httpx.AsyncClient(follow_redirects=False, timeout=UPSTREAM_HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.request(
            request.method,
            url,
            params=params,
            headers=headers,
            content=body,
        )

    out_headers = _strip_hop_by_hop_headers(dict(resp.headers))
    # Avoid caching capability URLs
    out_headers["cache-control"] = "no-store"

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=out_headers,
        media_type=resp.headers.get("content-type"),
    )


# -------------------------
# web_tty capability: WebSocket proxy
# -------------------------
@APP.websocket("/v1/cap/web_tty/{sid}/ws")
async def cap_web_tty_ws(ws: WebSocket, sid: str):
    _require_websockets()

    cap = ws.query_params.get("cap", "")
    # Accept first so we can close with proper code
    await ws.accept()

    # Build a minimal Request-like context for SAT + OPA input
    # (FastAPI doesn't give Request in ws routes; we assemble the bits we need)
    class _WSReq:
        def __init__(self, ws_: WebSocket):
            self.headers = ws_.headers
            self.client = ws_.client

    faux_request = _WSReq(ws)  # type: ignore

    try:
        require_sat(faux_request)  # type: ignore
        claims = verify_cap_token(cap, scenario_id=sid, capability="web_tty")
        enforce_single_use(jti=str(claims["jti"]), exp=int(claims["exp"]))

        input_doc = {
            "request_id": ws.headers.get("X-Request-Id", str(claims.get("jti"))),
            "tenant_id": claims.get("tenant_id"),
            "subject": claims.get("sub"),
            "scenario_id": sid,
            "track": claims.get("track"),
            "capability": "web_tty",
            "source_ip": (ws.headers.get("x-forwarded-for", "").split(",")[0].strip() if ws.headers.get("x-forwarded-for") else (ws.client.host if ws.client else None)),
            "user_agent": ws.headers.get("user-agent"),
            "token_exp": int(claims.get("exp", 0)),
            "tenant_blocked": False,
            "track_allowlist_enabled": False,
            "track_allowlist": {},
        }

        allowed = await opa_allow(input_doc)
        if not allowed:
            deny = await opa_deny_reasons(input_doc)
            audit(
                "access.capability_denied",
                {
                    "scenario_id": sid,
                    "subject": claims.get("sub"),
                    "tenant_id": claims.get("tenant_id"),
                    "capability": "web_tty",
                    "jti": claims.get("jti"),
                    "deny_reasons": deny,
                    "cap_hash": _token_hash(cap),
                    "ws": True,
                },
            )
            await ws.send_json({"error": "denied", "deny_reasons": deny})
            await ws.close(code=4403)
            return

    except HTTPException as he:
        # Map to WS close codes
        code = 4401 if he.status_code == 401 else 4403
        try:
            await ws.send_json({"error": "unauthorized", "detail": he.detail})
        except Exception:
            pass
        await ws.close(code=code)
        return
    except Exception:
        await ws.close(code=1011)
        return

    audit(
        "access.session_started",
        {
            "scenario_id": sid,
            "subject": claims.get("sub"),
            "tenant_id": claims.get("tenant_id"),
            "capability": "web_tty",
            "jti": claims.get("jti"),
            "cap_hash": _token_hash(cap),
            "ws": True,
        },
    )

    upstream = _upstream_ws(sid)

    session_start = time.monotonic()
    last_activity = time.monotonic()

    async def _close(reason: str):
        audit(
            "access.session_closed",
            {
                "scenario_id": sid,
                "subject": claims.get("sub"),
                "tenant_id": claims.get("tenant_id"),
                "capability": "web_tty",
                "jti": claims.get("jti"),
                "reason": reason,
                "ws": True,
            },
        )
        try:
            await ws.close()
        except Exception:
            pass

    async def _pump_client_to_up(up):
        nonlocal last_activity
        try:
            while True:
                msg = await ws.receive()
                now = time.monotonic()
                last_activity = now

                # Enforce max lifetime
                if now - session_start > TTY_MAX_SECONDS:
                    break

                if "text" in msg and msg["text"] is not None:
                    data = msg["text"]
                    if isinstance(data, str) and len(data.encode("utf-8")) > WS_MAX_MESSAGE_BYTES:
                        break
                    await up.send(data)
                elif "bytes" in msg and msg["bytes"] is not None:
                    b = msg["bytes"]
                    if b is not None and len(b) > WS_MAX_MESSAGE_BYTES:
                        break
                    await up.send(b)
                else:
                    break
        except WebSocketDisconnect:
            pass
        except Exception:
            pass

    async def _pump_up_to_client(up):
        nonlocal last_activity
        try:
            async for msg in up:
                now = time.monotonic()
                last_activity = now

                if now - session_start > TTY_MAX_SECONDS:
                    break

                if isinstance(msg, (bytes, bytearray)):
                    if len(msg) > WS_MAX_MESSAGE_BYTES:
                        break
                    await ws.send_bytes(msg)
                else:
                    if len(str(msg).encode("utf-8")) > WS_MAX_MESSAGE_BYTES:
                        break
                    await ws.send_text(str(msg))
        except Exception:
            pass

    async def _watchdog():
        # Enforce idle timeout and max lifetime
        while True:
            await asyncio.sleep(1)
            now = time.monotonic()
            if now - session_start > TTY_MAX_SECONDS:
                return "max"
            if now - last_activity > TTY_IDLE_SECONDS:
                return "idle"

    try:
        async with websockets.connect(upstream, max_size=WS_MAX_MESSAGE_BYTES) as up:
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(_pump_client_to_up(up)),
                    asyncio.create_task(_pump_up_to_client(up)),
                    asyncio.create_task(_watchdog()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # If watchdog finished, close; otherwise one side disconnected
            reason = "closed"
            for t in done:
                if t.get_coro().__name__ == "_watchdog":
                    try:
                        reason = t.result()
                    except Exception:
                        reason = "closed"

            for t in pending:
                t.cancel()

            await _close(reason=reason)

    except Exception:
        await _close(reason="error")
        return
