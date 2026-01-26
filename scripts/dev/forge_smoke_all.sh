#!/bin/sh
set -eu

BASE_URL="${BASE_URL:-http://127.0.0.1:8082}"
OPA_INNER_URL="${OPA_INNER_URL:-http://forge_opa:8181}"   # only valid inside compose network
SUBJECT="${SUBJECT:-dev-user}"
TRACK="${TRACK:-netplus}"
REQ_ID="${REQ_ID:-bug-$(date +%s)}"

echo "== Forge smoke (host + compose) =="
echo "BASE_URL=$BASE_URL SUBJECT=$SUBJECT TRACK=$TRACK REQ_ID=$REQ_ID"
echo

echo "== Spawn readyz =="
curl -fsS "$BASE_URL/readyz" | cat; echo
echo

echo "== Spawn OpenAPI: /v1/spawn request schema (required fields) =="
# no jq dependency; use python if available; fall back to raw
if command -v python >/dev/null 2>&1; then
  python - <<PY
import json,urllib.request
spec=json.loads(urllib.request.urlopen("$BASE_URL/openapi.json", timeout=3).read().decode())
op=spec["paths"]["/v1/spawn"]["post"]
rb=op["requestBody"]["content"]["application/json"]["schema"]
name=rb.get("\$ref","").split("/")[-1]
schema=spec["components"]["schemas"].get(name, rb)
print("Required:", schema.get("required"))
print("Properties:", sorted((schema.get("properties") or {}).keys()))
PY
else
  echo "(python not found on host, skipping schema parse)"
fi
echo

echo "== Host spawn call: POST /v1/spawn =="
code="$(curl -sS -o /tmp/spawn.out -w "%{http_code}" \
  -H "x-request-id: $REQ_ID" \
  -H "content-type: application/json" \
  -X POST "$BASE_URL/v1/spawn" \
  -d "{\"track\":\"$TRACK\",\"subject\":\"$SUBJECT\"}" || true)"

echo "HTTP_CODE=$code"
cat /tmp/spawn.out; echo
echo

if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "202" ]; then
  echo "OK: spawn accepted"
  exit 0
fi

# Entitlement error is the expected failure mode right now
if grep -qi "entitlement not found" /tmp/spawn.out 2>/dev/null; then
  cat <<'TXT'
== FIX REQUIRED: dev entitlement fallback ==

OpenAPI exposes no entitlement endpoints, so the service must support dev seeding.

Add to compose.yml -> forge_spawn_service.environment:

  ENTITLEMENT_ALLOW_ALL: "true"
  ENTITLEMENT_DEFAULT_TIER: "basic"
  # Optional deterministic seed for CI (if you implement loader):
  # ENTITLEMENTS_JSON: '[{"subject":"dev-user","tier":"basic","tracks":["netplus","ccna","cissp"]}]'

Then:

  docker compose up -d --force-recreate forge_spawn_service
  scripts/forge_smoke_all.sh

Implementation behavior (recommended):
- If BILLING_MODE=stub and ENTITLEMENT_ALLOW_ALL=true:
    treat any subject as entitled for allowed tracks (or all tracks in dev).
- If ENTITLEMENTS_JSON is set:
    parse it at startup; entitlement match is (subject, track).
TXT
fi

echo "== Recent spawn logs (last 200 lines) =="
docker compose logs --tail=200 forge_spawn_service 2>/dev/null | sed -n '1,200p' || true
echo

echo "FAILED (HTTP $code)"
exit 1
