#!/usr/bin/env bash
set -euo pipefail

STUB_PATH="/tmp/orchestrator_stub.py"
PORT=9999

echo "[*] Writing orchestrator stub to $STUB_PATH"

cat > "$STUB_PATH" <<'PY'
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI()

@app.get("/ping")
async def ping(request: Request):
    return {"ok": True, "path": str(request.url.path), "received": None}

@app.post("/v1/scenarios")
async def create_scenario(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = None

    return JSONResponse(
        status_code=200,
        content={
            "ok": True,
            "received": payload,
        },
    )

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9999, log_level="info")
PY

echo "[*] Killing anything already listening on :$PORT"
PID=$(lsof -t -iTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)
if [[ -n "${PID}" ]]; then
  kill -TERM ${PID} 2>/dev/null || true
  sleep 0.3
fi

echo "[*] Starting orchestrator stub on http://127.0.0.1:$PORT"
python "$STUB_PATH"
