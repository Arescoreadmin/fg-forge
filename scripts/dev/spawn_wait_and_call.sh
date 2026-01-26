#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8082}"
TRACK="${TRACK:-netplus}"
SUBJECT="${SUBJECT:-dev-user}"
REQ_ID="${REQ_ID:-bug-$(date +%s)}"

echo "== wait for readyz =="
for i in {1..60}; do
  code="$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/readyz" || true)"
  if [[ "$code" == "200" ]]; then
    echo "readyz=200"
    break
  fi
  sleep 0.25
  if [[ "$i" == "60" ]]; then
    echo "readyz never went 200 (last=$code)"
    exit 1
  fi
done

echo
echo "== POST /v1/spawn =="
echo "BASE_URL=$BASE_URL TRACK=$TRACK SUBJECT=$SUBJECT REQ_ID=$REQ_ID"

tmp_h="$(mktemp)"
tmp_b="$(mktemp)"
trap 'rm -f "$tmp_h" "$tmp_b"' EXIT

curl -sS -D "$tmp_h" -o "$tmp_b" \
  -H "x-request-id: $REQ_ID" \
  -H "content-type: application/json" \
  -X POST "$BASE_URL/v1/spawn" \
  -d "{\"track\":\"$TRACK\",\"subject\":\"$SUBJECT\"}" || true

status="$(head -n1 "$tmp_h" || true)"
code="$(awk 'NR==1{print $2}' "$tmp_h" 2>/dev/null || true)"

echo "$status"
cat "$tmp_b"; echo
echo "HTTP_CODE=${code:-unknown}"

if [[ "${code:-}" != "200" ]]; then
  echo
  echo "== spawn_service logs (filtered) =="
  docker compose logs --tail=250 forge_spawn_service | rg -n "spawn|OPA|entitlement|tier|SAT|ET|ERROR|Traceback|$REQ_ID" || true
  exit 1
fi
scenario_id="$(python - <<PY
import json
print(json.load(open("$tmp_b"))["scenario_id"])
PY
)"
access_url="$(python - <<PY
import json
print(json.load(open("$tmp_b"))["access_url"])
PY
)"

echo
echo "== GET /v1/access/{scenario_id} (token validation) =="
code2="$(curl -sS -o /tmp/access.b -w "%{http_code}" "$access_url" || true)"
echo "HTTP_CODE=$code2"
cat /tmp/access.b; echo
test "$code2" = "200"

echo
echo "OK"
