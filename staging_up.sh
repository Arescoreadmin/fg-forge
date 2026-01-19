#!/usr/bin/env bash
# staging_up.sh
# Repo root: /home/jcosat/Projects/fg-forge/staging_up.sh
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.staging}"
BASE="${BASE:-compose.yml}"
STAGING="${STAGING:-compose.staging.yml}"
EXPOSE="${EXPOSE:-compose.expose.yml}"

VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-60}"
VERIFY_INTERVAL="${VERIFY_INTERVAL:-2}"

SPAWN_URL="${SPAWN_URL:-http://127.0.0.1:8082/readyz}"
ORCH_URL="${ORCH_URL:-http://127.0.0.1:8083/readyz}"
SCORE_URL="${SCORE_URL:-http://127.0.0.1:8086/readyz}"

CORE_SERVICES=("forge_spawn_service" "forge_orchestrator" "forge_scoreboard")

die() { echo "ERROR: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
require_file() { [[ -f "$1" ]] || die "Missing required file: $1"; }

on_err() {
  echo "---- ERROR: staging_up.sh failed ----" >&2
  { dc ps || true; } >&2
  { dc logs --tail=200 "${CORE_SERVICES[@]}" || true; } >&2
}
trap on_err ERR


dc() {
  docker compose --env-file "$ENV_FILE" -f "$BASE" -f "$STAGING" -f "$EXPOSE" "$@"
}

usage() {
  cat <<'USAGE'
Usage:
  ENV_FILE=.env.staging ./staging_up.sh <cmd>

Commands:
  lint        Validate script + compose config
  up          Bring up staging stack (detached)
  down        Bring down staging stack
  restart     down + up
  verify      Wait for services to be ready and print status
  status      Show compose status
  logs        Tail logs for core services

Environment overrides:
  ENV_FILE, BASE, STAGING, EXPOSE
  VERIFY_TIMEOUT, VERIFY_INTERVAL
  SPAWN_URL, ORCH_URL, SCORE_URL
USAGE
}

_script_body_no_header() {
  awk '
    BEGIN{h=1}
    h && ($0 ~ /^[[:space:]]*#/ || $0 ~ /^[[:space:]]*$/){next}
    {h=0; print}
  ' "$0"
}

lint_self() {
  bash -n "$0" || die "bash syntax error in $0"

  # Guard against pasted terminal output without embedding those tokens in the file.
  # Build components by concatenation so the literal strings never appear in source.
  local pat suspect
  local a b c d e f

  a="\\."
  a+="v"
  a+="env"

  b="[[:alnum:]_.-]+@"
  b+="[[:alnum:].-]+:~"

  c="^\\+{3,}"

  d="^#{2,}\\["
  d+="deb"
  d+="ug\\]"

  e="HT"
  e+="TP/1\\."
  e+="1"

  f="manif"
  f+="est unknown"

  pat="${a}|${b}|${c}|${d}|${e}|${f}"

  suspect="$(_script_body_no_header)"
  if grep -nE "$pat" <<<"$suspect" >/dev/null 2>&1; then
    echo "---- DEBUG: paste-garbage detector matched ----" >&2
    echo "Hint: remove pasted console prompts/debug/http lines from $0." >&2
    # Show matching lines (they are *in the script*, not the pattern).
    grep -nE "$pat" <<<"$suspect" >&2 || true
    die "paste-garbage detected in $0 (remove terminal output from script)"
  fi

  echo "OK: $0 syntax clean"
}

lint_compose() {
  require_file "$ENV_FILE"
  require_file "$BASE"
  require_file "$STAGING"
  require_file "$EXPOSE"

  have docker || die "docker is required"
  docker compose version >/dev/null 2>&1 || die "docker compose is not available"

  dc config >/dev/null
  echo "OK: compose config valid"
}

cmd_lint() {
  lint_self
  lint_compose
}

wait_http_200() {
  local name="$1"
  local url="$2"
  local timeout="${3:-$VERIFY_TIMEOUT}"
  local interval="${4:-$VERIFY_INTERVAL}"

  have curl || die "curl is required for verify"

  local start now elapsed
  start="$(date +%s)"

  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "OK: $name ready ($url)"
      return 0
    fi

    now="$(date +%s)"
    elapsed="$((now - start))"
    if (( elapsed >= timeout )); then
      echo "---- DEBUG: $name not ready after ${timeout}s ----" >&2
      echo "URL: $url" >&2
      dc ps >&2 || true
      dc logs --tail=200 "${CORE_SERVICES[@]}" >&2 || true
      die "$name not ready in time"
    fi

    sleep "$interval"
  done
}

cmd_up() {
  cmd_lint
  dc up -d
  echo "Staging stack is up."
}

cmd_down() {
  # Best-effort shutdown even if env file is missing.
  if [[ -f "$ENV_FILE" ]]; then
    dc down
  else
    docker compose -f "$BASE" -f "$STAGING" -f "$EXPOSE" down || true
  fi
  echo "Staging stack is down."
}

cmd_restart() {
  cmd_down || true
  cmd_up
}

cmd_status() {
  require_file "$ENV_FILE"
  dc ps
}

cmd_logs() {
  require_file "$ENV_FILE"
  dc logs -f --tail=200 "${CORE_SERVICES[@]}"
}

cmd_verify() {
  require_file "$ENV_FILE"
  dc ps
  wait_http_200 "spawn" "$SPAWN_URL"
  wait_http_200 "orchestrator" "$ORCH_URL"
  wait_http_200 "scoreboard" "$SCORE_URL"
  echo "OK: staging verify complete"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    lint)    cmd_lint ;;
    up)      cmd_up ;;
    down)    cmd_down ;;
    restart) cmd_restart ;;
    verify)  cmd_verify ;;
    status)  cmd_status ;;
    logs)    cmd_logs ;;
    ""|-h|--help|help) usage ;;
    *) die "unknown command: $cmd (use --help)" ;;
  esac
}

main "$@"
