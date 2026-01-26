#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"

echo "== Ensure core services up =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f compose.netfix.yml up -d \
  forge_opa forge_nats forge_redis forge_minio \
  forge_spawn_service forge_orchestrator forge_worker_agent \
  forge_metrics_tuner forge_egress_gateway forge_llm_analyzer forge_scoreboard >/dev/null

echo "== 1) Spawn (8082) =="
REQ_ID="req-$(date +%s)"
SPAWN_JSON="$(curl -fsS -X POST http://127.0.0.1:8082/v1/spawn \
  -H 'content-type: application/json' \
  -d "{\"track\":\"netplus\",\"subject\":\"forge\",\"request_id\":\"${REQ_ID}\",\"template_id\":\"netplus\"}")"

echo "$SPAWN_JSON" | jq .
SCENARIO_ID="$(echo "$SPAWN_JSON" | jq -r .scenario_id)"
SAT="$(echo "$SPAWN_JSON" | jq -r .sat)"
echo "scenario_id=$SCENARIO_ID"
echo "sat_len=${#SAT}"
test "${#SAT}" -gt 50

echo
echo "== 2) Create scenario in orchestrator (8083) with SAT =="
REQ_ID="orch-$(date +%s)"
HTTP_CODE="$(curl -sS -o /tmp/orch_create.json -w '%{http_code}' \
  -X POST http://127.0.0.1:8083/v1/scenarios \
  -H 'content-type: application/json' \
  -H "X-SAT: ${SAT}" \
  -d "{\"scenario_id\":\"${SCENARIO_ID}\",\"template\":\"netplus\",\"request_id\":\"${REQ_ID}\",\"tier\":\"TEAM\"}")"

echo "orchestrator create HTTP=$HTTP_CODE"
cat /tmp/orch_create.json | sed -n '1,200p'
echo
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "ERROR: orchestrator create failed"
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f compose.netfix.yml logs --tail=120 forge_orchestrator
  exit 1
fi

echo
echo "== 3) List scenarios (8083) =="
curl -fsS http://127.0.0.1:8083/v1/scenarios | jq .

echo
echo "== 4) Confirm scenario event in JetStream (QUOTA stream includes scenario.>) =="
docker run --rm --network forge_platform natsio/nats-box:latest sh -lc "
set -e
nats --server nats://forge_nats:4222 stream info QUOTA | sed -n '1,80p'
echo
# Pull last few msgs from QUOTA and grep scenario id
nats --server nats://forge_nats:4222 stream view QUOTA --count 20 --raw | tr -d '\r' | grep -F \"$SCENARIO_ID\" -n || true
"

echo
echo "DONE: spawn + SAT + orchestrator create path is healthy"
