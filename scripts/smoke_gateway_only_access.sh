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
