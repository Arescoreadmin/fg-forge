#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.staging}"
BASE="compose.yml"
STAGING="compose.staging.yml"
EXPOSE="compose.expose.yml"

dc() {
  docker compose --env-file "$ENV_FILE" -f "$BASE" -f "$STAGING" -f "$EXPOSE" "$@"
}

need_file() {
  [[ -f "$1" ]] || { echo "Missing required file: $1" >&2; exit 1; }
}

cleanup_fix_container() {
  docker ps -a --format '{{.Names}}' | grep -E 'forge_scoreboard_storage_fix' | xargs -r docker rm -f >/dev/null 2>&1 || true
}

echo "[1/8] Preflight checks"
need_file "$ENV_FILE"
need_file "$BASE"
need_file "$EXPOSE"

echo "[2/8] Writing ${STAGING}"
cat > "$STAGING" <<'YAML'
# compose.staging.yml
# Staging overrides:
# - Disable published app ports (compose.expose.yml controls exposure)
# - Enforce required secrets/tokens
# - Add MinIO readiness gate (probe sharing MinIO netns)
# - Fix scoreboard volume permissions via one-shot job

services:
  forge_spawn_service:
    environment:
      BILLING_MODE: stripe
      SAT_HMAC_SECRET: ${SAT_HMAC_SECRET:?required}
    ports: []

  forge_orchestrator:
    environment:
      ORCHESTRATOR_INTERNAL_TOKEN: ${ORCHESTRATOR_INTERNAL_TOKEN:?required}
      OPERATOR_TOKEN: ${OPERATOR_TOKEN:?required}
      SCOREBOARD_INTERNAL_TOKEN: ${SCOREBOARD_INTERNAL_TOKEN:?required}
      SAT_HMAC_SECRET: ${SAT_HMAC_SECRET:?required}
    ports: []

  forge_scoreboard_storage_fix:
    image: alpine:3.19
    command: ["sh", "-lc", "chown -R 1000:1000 /data && ls -ld /data"]
    volumes:
      - forge_scoreboard_storage:/data
    restart: "no"

  forge_scoreboard:
    environment:
      SCOREBOARD_INTERNAL_TOKEN: ${SCOREBOARD_INTERNAL_TOKEN:?required}
    user: "1000:1000"
    ports: []
    depends_on:
      forge_scoreboard_storage_fix:
        condition: service_completed_successfully
      forge_minio_probe:
        condition: service_healthy

  forge_worker_agent:
    ports: []
    depends_on:
      forge_minio_probe:
        condition: service_healthy

  forge_overlay_sanitizer:
    ports: []
    depends_on:
      forge_minio_probe:
        condition: service_healthy

  forge_observer_hub: { ports: [] }
  forge_playbook_runner: { ports: [] }
  forge_metrics_tuner: { ports: [] }
  forge_egress_gateway: { ports: [] }
  forge_llm_analyzer: { ports: [] }

  # staging-only MinIO gate (probe shares MinIO network namespace, so 127.0.0.1:9000 is MinIO)
  forge_minio_probe:
    image: curlimages/curl:8.5.0
    command: ["sh", "-lc", "sleep infinity"]
    restart: unless-stopped
    depends_on:
      forge_minio:
        condition: service_started
    network_mode: "service:forge_minio"
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:9000/minio/health/live >/dev/null || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 60
      start_period: 30s

volumes:
  forge_scoreboard_storage: {}
YAML

echo "[3/8] Validating merged compose config"
dc config >/dev/null

echo "[4/8] Booting core deps (redis/nats/opa/minio)"
dc up -d --remove-orphans forge_redis forge_nats forge_opa forge_minio

echo "[5/8] Starting MinIO probe"
dc up -d --force-recreate forge_minio_probe

echo "[6/8] Fixing scoreboard storage perms (one-shot)"
cleanup_fix_container
dc up -d forge_scoreboard_storage_fix

echo "[7/8] Starting scoreboard + orchestrator"
dc up -d --force-recreate forge_scoreboard
dc up -d forge_orchestrator

echo "[8/8] Ready checks + status"
echo
echo "---- STATUS ----"
dc ps forge_minio forge_minio_probe forge_scoreboard forge_orchestrator || true
echo
echo "---- READY CHECKS ----"
curl -fsS http://localhost:8086/readyz && echo "  # scoreboard ready"
curl -fsS http://localhost:8083/readyz && echo "  # orchestrator ready"
echo

cleanup_fix_container
echo "Staging stack is up."
