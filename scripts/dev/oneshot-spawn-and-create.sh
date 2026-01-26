#!/usr/bin/env bash
set -euo pipefail

SPAWN_URL="${SPAWN_URL:-http://127.0.0.1:8082}"
ORCH_URL="${ORCH_URL:-http://127.0.0.1:8083}"
TRACK="${TRACK:-netplus}"
SUBJECT="${SUBJECT:-forge}"
TEMPLATE="${TEMPLATE:-netplus}"
TIER="${TIER:-TEAM}"

REQ_ID="req-$(date +%s)"

echo "== Spawn =="
SPAWN_RAW="$(curl -sS -i -X POST "$SPAWN_URL/v1/spawn" \
  -H 'content-type: application/json' \
  -H "x-request-id: $REQ_ID" \
  -d "{\"track\":\"$TRACK\",\"subject\":\"$SUBJECT\"}")"

echo "$SPAWN_RAW" | sed -n '1,80p'

SPAWN_BODY="$(echo "$SPAWN_RAW" | sed -n '/^\r\{0,1\}$/,$p' | tail -n +2)"
SCENARIO_ID="$(echo "$SPAWN_BODY" | jq -r '.scenario_id // empty')"
SAT="$(echo "$SPAWN_BODY" | jq -r '.sat // empty')"

if [[ -z "$SCENARIO_ID" || -z "$SAT" ]]; then
  echo "ERROR: spawn did not return scenario_id/sat"
  echo "$SPAWN_BODY"
  exit 1
fi

echo
echo "scenario_id=$SCENARIO_ID"
echo "sat_len=${#SAT}"

echo
echo "== Orchestrator create =="
CREATE_BODY="$(jq -n \
  --arg sid "$SCENARIO_ID" \
  --arg rid "orch-$REQ_ID" \
  --arg tpl "$TEMPLATE" \
  --arg tier "$TIER" \
  '{scenario_id:$sid, template:$tpl, request_id:$rid, tier:$tier}')"

curl -sS -i -X POST "$ORCH_URL/v1/scenarios" \
  -H 'content-type: application/json' \
  -H "X-SAT: $SAT" \
  -d "$CREATE_BODY" | sed -n '1,160p'
