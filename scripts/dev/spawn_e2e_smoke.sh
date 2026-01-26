#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8082}"
TRACK="${TRACK:-netplus}"
SUBJECT="${SUBJECT:-dev-user}"
REQ_ID="${REQ_ID:-bug-$(date +%s)}"

echo "== Spawn E2E smoke =="
echo "BASE_URL=$BASE_URL TRACK=$TRACK SUBJECT=$SUBJECT REQ_ID=$REQ_ID"

echo
echo "== readyz =="
curl -fsS "$BASE_URL/readyz" | cat; echo

echo
echo "== seed entitlement (best effort; may fail if you haven't implemented it) =="
scripts/seed_entitlement_best_effort.sh BASE_URL="$BASE_URL" SUBJECT="$SUBJECT" || true

echo
echo "== POST /v1/spawn =="
resp="$(mktemp)"
hdrs="$(mktemp)"
trap 'rm -f "$resp" "$hdrs"' EXIT

code=$(curl -sS -D "$hdrs" -o "$resp" -w "%{http_code}" \
  -H "x-request-id: $REQ_ID" \
  -H "content-type: application/json" \
  -X POST "$BASE_URL/v1/spawn" \
  -d "{\"track\":\"$TRACK\",\"subject\":\"$SUBJECT\"}" || true)

echo "HTTP_CODE=$code"
head -n1 "$hdrs" || true
cat "$resp"; echo

echo
echo "== Spawn service logs (filtered) =="
docker compose logs --tail=200 forge_spawn_service | rg -n "$REQ_ID|entitle|entitlement|OPA|deny_reasons|api_usage_warning|subject" || true

if [[ "$code" =~ ^2 ]]; then
  echo
  echo "OK"
  exit 0
fi

echo
echo "FAILED (HTTP $code). If you still see 'entitlement not found', implement:"
echo "  - BILLING_MODE=stub + ENTITLEMENT_ALLOW_ALL=true (dev)"
echo "  - or ENTITLEMENTS_JSON and load it at startup"
exit 1
