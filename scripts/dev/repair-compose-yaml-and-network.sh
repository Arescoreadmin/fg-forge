#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
NETFIX_FILE="${NETFIX_FILE:-compose.netfix.yml}"
NETWORK_NAME="${NETWORK_NAME:-forge_platform}"

cd "$ROOT_DIR"

echo "== Repair: restore latest compose backups (if present) =="

restore_latest() {
  local base="$1"
  local latest
  latest="$(ls -1 "${base}.bak_"* 2>/dev/null | sort | tail -n 1 || true)"
  if [[ -n "${latest}" ]]; then
    echo "Restoring ${base} from ${latest}"
    cp -a "${latest}" "${base}"
  else
    echo "No backups found for ${base} (skipping restore)"
  fi
}

restore_latest "$COMPOSE"
restore_latest "$EXPOSE_FILE"

echo
echo "== Write network override: $NETFIX_FILE =="

cat > "$NETFIX_FILE" <<YAML
# compose.netfix.yml
# Minimal override to force a stable network name across all compose files.
networks:
  default:
    name: ${NETWORK_NAME}
YAML

echo
echo "== Validate merged compose config =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f "$NETFIX_FILE" config >/dev/null
echo "OK: compose config parses"

echo
echo "== Bring up OPA and probes (to validate DNS + health) =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f "$NETFIX_FILE" up -d --force-recreate \
  forge_opa forge_opa_probe forge_nats forge_nats_probe >/dev/null

echo
echo "== DNS check inside ${NETWORK_NAME} =="
docker run --rm --network "${NETWORK_NAME}" busybox:1.36 sh -lc 'nslookup forge_opa >/dev/null && echo "OK: forge_opa resolves"'

echo
echo "== OPA health from inside network =="
docker run --rm --network "${NETWORK_NAME}" curlimages/curl:8.5.0 sh -lc '
for i in $(seq 1 60); do
  curl -fsS http://forge_opa:8181/health?plugins >/dev/null && { echo "OPA healthy"; exit 0; }
  sleep 1
done
echo "ERROR: OPA not healthy"; exit 1
'

echo
echo "== Query OPA decision endpoint sanity check =="
docker run --rm --network "${NETWORK_NAME}" curlimages/curl:8.5.0 sh -lc '
payload='\''{"input":{"track":"netplus","details":{"track":"netplus"},"metadata":{"labels":{"track":"netplus"}},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'\''
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/decision \
  -H "content-type: application/json" \
  -d "$payload" | sed -n "1,200p"
'

echo
echo "DONE: compose repaired + network stabilized via $NETFIX_FILE"
echo "Use this in all commands:  -f $COMPOSE -f $EXPOSE_FILE -f $NETFIX_FILE"
