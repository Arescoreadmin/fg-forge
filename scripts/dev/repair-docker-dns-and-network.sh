#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
NETFIX_FILE="${NETFIX_FILE:-compose.netfix.yml}"
NETWORK_NAME="${NETWORK_NAME:-forge_platform}"

cd "$ROOT_DIR"

dc() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f "$NETFIX_FILE" "$@"
}

echo "== 0) Validate compose config =="
dc config >/dev/null
echo "OK"

echo "== 1) Snapshot current network + container status (for receipts) =="
docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 && {
  echo "-- network $NETWORK_NAME exists --"
  docker network inspect "$NETWORK_NAME" | jq '.[0] | {Name,Id,Driver,Containers:(.Containers|keys)}' || true
} || {
  echo "-- network $NETWORK_NAME does not exist (yet) --"
}

for c in forge_opa forge_nats forge_redis forge_minio forge_scoreboard forge_orchestrator forge_spawn_service; do
  if docker inspect "$c" >/dev/null 2>&1; then
    echo "-- $c networks --"
    docker inspect -f '{{json .NetworkSettings.Networks}}' "$c" | jq . || true
  else
    echo "-- $c missing --"
  fi
done

echo "== 2) Hard reset: bring stack down (keep volumes) =="
# Keep volumes. Only remove containers + network attachments.
dc down --remove-orphans

echo "== 3) Remove corrupted network (if present) =="
if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  # If anything is still attached, force-disconnect it.
  attached="$(docker network inspect "$NETWORK_NAME" -f '{{json .Containers}}' | jq -r 'keys[]?' || true)"
  if [[ -n "${attached:-}" ]]; then
    echo "Detaching leftover endpoints from $NETWORK_NAME..."
    while read -r id; do
      [[ -z "$id" ]] && continue
      docker network disconnect -f "$NETWORK_NAME" "$id" >/dev/null 2>&1 || true
    done <<< "$attached"
  fi
  docker network rm "$NETWORK_NAME"
  echo "Removed network: $NETWORK_NAME"
else
  echo "Network $NETWORK_NAME not present, skipping rm"
fi

echo "== 4) Recreate core infra + probes first (network will be recreated by compose) =="
dc up -d forge_opa forge_opa_probe forge_nats forge_nats_probe forge_redis forge_minio forge_minio_probe >/dev/null

echo "== 5) Wait for OPA probe healthy =="
# If this fails, we want logs immediately.
for i in $(seq 1 90); do
  status="$(docker inspect -f '{{.State.Health.Status}}' forge_opa_probe 2>/dev/null || echo "unknown")"
  if [[ "$status" == "healthy" ]]; then
    echo "forge_opa_probe healthy"
    break
  fi
  if [[ "$i" -eq 90 ]]; then
    echo "ERROR: forge_opa_probe not healthy"
    docker logs --tail=200 forge_opa || true
    docker logs --tail=200 forge_opa_probe || true
    exit 1
  fi
  sleep 1
done

echo "== 6) Verify forge_opa has a real endpoint + IP on $NETWORK_NAME =="
docker inspect -f '{{json .NetworkSettings.Networks}}' forge_opa | jq .
OPA_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$NETWORK_NAME"'").IPAddress}}' forge_opa || true)"
OPA_EPID="$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$NETWORK_NAME"'").EndpointID}}' forge_opa || true)"

if [[ -z "${OPA_IP:-}" || "${OPA_IP:-}" == "<no value>" || -z "${OPA_EPID:-}" || "${OPA_EPID:-}" == "<no value>" ]]; then
  echo "ERROR: forge_opa still has no IP/Endpoint on $NETWORK_NAME (DNS will not work)."
  echo "OPA_IP='$OPA_IP' OPA_EPID='$OPA_EPID'"
  docker logs --tail=200 forge_opa || true
  exit 1
fi
echo "forge_opa IP=$OPA_IP endpoint=$OPA_EPID"

echo "== 7) DNS + HTTP checks from inside the network =="
docker run --rm --network "$NETWORK_NAME" busybox:1.36 nslookup forge_opa
docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 curl -fsS http://forge_opa:8181/health?plugins >/dev/null
echo "DNS and HTTP to forge_opa OK"

echo "== 8) Bring up app services now that DNS is sane =="
dc up -d forge_scoreboard forge_orchestrator forge_spawn_service forge_worker_agent forge_metrics_tuner forge_egress_gateway forge_llm_analyzer >/dev/null

echo "== 9) Quick health summary =="
for svc in forge_opa_probe forge_nats_probe forge_minio_probe forge_scoreboard forge_orchestrator forge_spawn_service; do
  echo "-- $svc --"
  docker ps --filter "name=^/${svc}$" --format 'table {{.Names}}\t{{.Status}}' || true
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$svc" 2>/dev/null || true
done

echo "DONE"
