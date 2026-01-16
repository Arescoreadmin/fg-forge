#!/usr/bin/env bash
# staging_up.sh
# Repo root: /home/jcosat/Projects/fg-forge/staging_up.sh
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.staging}"
BASE="${BASE:-compose.yml}"
STAGING="${STAGING:-compose.staging.yml}"
EXPOSE="${EXPOSE:-compose.expose.yml}"
FORCE_WRITE="${FORCE_WRITE:-0}"

dc() {
  docker compose --env-file "$ENV_FILE" -f "$BASE" -f "$STAGING" -f "$EXPOSE" "$@"
}

die() { echo "ERROR: $*" >&2; exit 1; }

need_file() {
  [[ -f "$1" ]] || die "Missing required file: $1"
}

cleanup_fix_container() {
  docker ps -a --format '{{.Names}}' | grep -E 'forge_scoreboard_storage_fix' | xargs -r docker rm -f >/dev/null 2>&1 || true
  dc rm -sf forge_scoreboard_storage_fix >/dev/null 2>&1 || true
}

verify_staging_file() {
  [[ -f "$STAGING" ]] || die "$STAGING missing (run: ./staging_up.sh write)"
  grep -q '^volumes:$' "$STAGING" || die "$STAGING looks truncated (missing volumes:)"
  grep -q '^  forge_minio_probe:' "$STAGING" || die "$STAGING missing forge_minio_probe"
  grep -q '^  forge_scoreboard_storage_fix:' "$STAGING" || die "$STAGING missing forge_scoreboard_storage_fix"
  echo "OK: $STAGING integrity checks passed"
}

write_staging_file() {
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

  # staging-only MinIO readiness gate (shares MinIO network namespace)
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

  verify_staging_file
}

# curl helper: retry because uvicorn can reset connections during boot
wait_http_ok() {
  local url="$1"
  local label="$2"
  local tries="${3:-30}"
  local sleep_s="${4:-1}"

  local i
  for i in $(seq 1 "$tries"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "OK: ${label}"
      return 0
    fi
    sleep "$sleep_s"
  done

  return 1
}

lint_self() {
  bash -n "$0" || die "bash -n failed"

  # Only flag known paste-corruption shards.
  # Exclusions: YAML heredoc, usage(), and lint_self() itself.
  local pat
  pat='truedev|null \|\| exit 1"\]\\-f|clean"g_up\.sh|\.tmp staging_up\.sh|g_up\.sh up\.|up\."8083/readyz'

  if awk '
    BEGIN {in_yaml=0; in_usage=0; in_lint=0}
    /<<'\''YAML'\''/ {in_yaml=1; next}
    in_yaml && /^YAML$/ {in_yaml=0; next}

    /^usage\(\)[[:space:]]*\{/ {in_usage=1}
    in_usage && /^\}/ {in_usage=0; next}

    /^lint_self\(\)[[:space:]]*\{/ {in_lint=1; next}
    in_lint && /^\}/ {in_lint=0; next}

    in_yaml || in_usage || in_lint {next}
    {print}
  ' "$0" | grep -nE "$pat" >/dev/null; then

    awk '
      BEGIN {in_yaml=0; in_usage=0; in_lint=0}
      /<<'\''YAML'\''/ {in_yaml=1; next}
      in_yaml && /^YAML$/ {in_yaml=0; next}

      /^usage\(\)[[:space:]]*\{/ {in_usage=1}
      in_usage && /^\}/ {in_usage=0; next}

      /^lint_self\(\)[[:space:]]*\{/ {in_lint=1; next}
      in_lint && /^\}/ {in_lint=0; next}

      in_yaml || in_usage || in_lint {next}
      {print NR ":" $0}
    ' "$0" | grep -nE "$pat" || true

    die "paste-garbage detected in $0"
  fi

  echo "OK: lint passed"
}

usage() {
  cat <<EOF
Usage:
  ./staging_up.sh up        # bring up staging stack (writes staging file only if missing; FORCE_WRITE=1 to overwrite)
  ./staging_up.sh write     # write compose.staging.yml (always)
  ./staging_up.sh verify    # verify env + compose.staging.yml + merged config
  ./staging_up.sh down      # stop stack (down --remove-orphans)
  ./staging_up.sh lint      # bash syntax + paste-corruption sanity check (excludes heredoc/usage/lint_self)

Env overrides:
  ENV_FILE=.env.staging     # default; override like ENV_FILE=.env.foo ./staging_up.sh up
  BASE=compose.yml
  STAGING=compose.staging.yml
  EXPOSE=compose.expose.yml
  FORCE_WRITE=1             # overwrite compose.staging.yml on up
EOF
}

cmd="${1:-up}"

case "$cmd" in
  lint)
    lint_self
    ;;
  write)
    need_file "$ENV_FILE"; need_file "$BASE"; need_file "$EXPOSE"
    write_staging_file
    ;;
  verify)
    need_file "$ENV_FILE"; need_file "$BASE"; need_file "$EXPOSE"
    verify_staging_file
    dc config >/dev/null
    echo "OK: merged config valid"
    ;;
  down)
    need_file "$ENV_FILE"; need_file "$BASE"; need_file "$EXPOSE"
    cleanup_fix_container
    dc down --remove-orphans || true
    echo "Staging stack is down."
    ;;
  up)
    echo "[1/8] Preflight checks"
    need_file "$ENV_FILE"
    need_file "$BASE"
    need_file "$EXPOSE"

    if [[ "$FORCE_WRITE" == "1" ]] || [[ ! -f "$STAGING" ]]; then
      write_staging_file
    else
      echo "[2/8] Skipping compose.staging.yml write (exists). Set FORCE_WRITE=1 to overwrite."
      verify_staging_file
    fi

    echo "[3/8] Validating merged compose config"
    dc config >/dev/null

    echo "[4/8] Booting core deps (redis/nats/opa/minio/spawn)"
    dc up -d --remove-orphans forge_redis forge_nats forge_opa forge_minio forge_spawn_service

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
    dc ps forge_minio forge_minio_probe forge_spawn_service forge_scoreboard forge_orchestrator || true
    echo
    echo "---- READY CHECKS ----"

    wait_http_ok "http://localhost:8086/readyz" "scoreboard ready" 30 1 || die "scoreboard not ready"
    wait_http_ok "http://localhost:8083/readyz" "orchestrator ready" 30 1 || die "orchestrator not ready"
    if wait_http_ok "http://localhost:8082/readyz" "spawn ready" 15 1; then
      :
    else
      echo "WARN: spawn not reachable on :8082 (expose?)"
    fi
    echo

    cleanup_fix_container
    echo "Staging stack is up."
    ;;
  *)
    usage
    exit 2
    ;;
esac
