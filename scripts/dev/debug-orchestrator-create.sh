#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
NETFIX_FILE="${NETFIX_FILE:-compose.netfix.yml}"

ORCH_HOST="${ORCH_HOST:-http://127.0.0.1:8083}"
ORCH_DOCKER_URL="${ORCH_DOCKER_URL:-http://forge_orchestrator:8080}"

SCENARIO_ID="${SCENARIO_ID:-}"
SAT="${SAT:-}"
TEMPLATE="${TEMPLATE:-netplus}"
TIER="${TIER:-TEAM}"

dc() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f "$NETFIX_FILE" "$@"
}

die() { echo "ERROR: $*" >&2; exit 1; }

echo "== Ensure orchestrator container exists =="
dc up -d forge_orchestrator >/dev/null

echo "== Orchestrator status =="
docker ps --filter name=forge_orchestrator --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true

echo "== Host readyz =="
curl -fsS "$ORCH_HOST/readyz" || {
  echo "--- host readyz failed ---"
  curl -v "$ORCH_HOST/readyz" || true
}

if [[ -z "$SCENARIO_ID" || -z "$SAT" ]]; then
  echo "NOTE: SCENARIO_ID and SAT must be exported from your spawn output."
  echo "Example:"
  echo '  export SCENARIO_ID="scn-..."'
  echo '  export SAT="eyJ..."'
  die "missing SCENARIO_ID or SAT"
fi

REQ_ID="orch-$(date +%s)"
BODY="$(jq -nc --arg sid "$SCENARIO_ID" --arg tpl "$TEMPLATE" --arg rid "$REQ_ID" --arg tier "$TIER" \
  '{scenario_id:$sid, template:$tpl, request_id:$rid, tier:$tier}')"

echo "== Create via host port (expect 200/4xx, not a reset) =="
set +e
HOST_OUT="$(curl -sS -D /tmp/orch_hdrs -o /tmp/orch_body \
  -X POST "$ORCH_HOST/v1/scenarios" \
  -H 'content-type: application/json' \
  -H "X-SAT: $SAT" \
  -d "$BODY" 2>&1)"
HOST_RC=$?
set -e

if [[ $HOST_RC -ne 0 ]]; then
  echo "--- curl error (host path) ---"
  echo "$HOST_OUT"
  echo
  echo "== Orchestrator container inspect (did it restart?) =="
  docker inspect forge_orchestrator --format \
    'State={{json .State}}' | sed -n '1,120p' || true
  echo
  echo "== Last orchestrator logs (stack trace lives here) =="
  docker logs --tail=250 forge_orchestrator || true
  echo
  echo "== Try create inside docker network (bypass expose) =="
  docker run --rm --network forge_platform curlimages/curl:8.5.0 sh -lc \
    "curl -v -sS -X POST '$ORCH_DOCKER_URL/v1/scenarios' \
      -H 'content-type: application/json' \
      -H 'X-SAT: $SAT' \
      -d '$BODY' | sed -n '1,220p'" || true
  exit 1
fi

echo "--- response headers ---"
sed -n '1,80p' /tmp/orch_hdrs
echo "--- response body ---"
sed -n '1,220p' /tmp/orch_body
echo "DONE"
