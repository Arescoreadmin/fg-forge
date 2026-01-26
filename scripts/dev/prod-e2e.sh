#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.prod}"

SAT_HMAC_SECRET="$(grep '^SAT_HMAC_SECRET=' "$ENV_FILE" | cut -d= -f2-)"
export SAT_HMAC_SECRET

export SAT_TRACK=netplus
export SAT_TEMPLATE_ID=netplus
export SAT_SUBJECT=prod-e2e-user
export SAT_TENANT_ID=prod
export SAT_TIER=ENTERPRISE

SAT="$(python /home/jcosat/Projects/fg-forge/scripts/mint-sat.py)"

REQ_ID="prod-e2e-$(date +%s)"
echo "REQ_ID=$REQ_ID"

echo "== spawn =="
curl -sS -i \
  -H "x-request-id: $REQ_ID" \
  -H "content-type: application/json" \
  -H "x-sat: $SAT" \
  -d '{"track":"netplus","subject":"prod-e2e-user"}' \
  http://127.0.0.1:8082/v1/spawn
echo
