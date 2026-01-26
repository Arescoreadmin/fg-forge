#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(pwd)}"
cd "$REPO_ROOT"

OUT_COMPOSE="${OUT_COMPOSE:-compose.yml}"

cat > "$OUT_COMPOSE" <<'YAML'
# compose.yml (dev base)
# - No version key (compose v2 ignores it)
# - Safe anchors (string mounts, not nested lists)
# - Infra is writable; apps are read-only
# - Healthchecks avoid assuming wget/curl in minimal images (use probe sidecars)
# - Designed to layer with compose.expose.yml + compose.staging.yml

x-app-defaults: &app_defaults
  read_only: true
  tmpfs:
    - /tmp
  cap_drop:
    - ALL
  security_opt:
    - no-new-privileges:true
  restart: unless-stopped
  networks:
    - default

x-infra-defaults: &infra_defaults
  read_only: false
  security_opt:
    - no-new-privileges:true
  restart: unless-stopped
  networks:
    - default

# IMPORTANT: anchor as a STRING (prevents nested-list volume errors)
x-templates-mount: &templates_mount ./templates:/templates:ro

services:
  # ----------------------------
  # App services (dev publishes ports)
  # ----------------------------

  forge_spawn_service:
    <<: *app_defaults
    build:
      context: ./services/spawn_service
    image: forge_spawn_service:local
    container_name: forge_spawn_service
    environment:
      FORGE_ENV: dev
      BILLING_MODE: stub
      SPAWN_BASE_URL: http://localhost:8082
      REQUEST_ID_HEADER: x-request-id
      TEMPLATE_DIR: /templates
      OPA_URL: http://forge_opa:8181
      NATS_URL: nats://forge_nats:4222
      SAT_HMAC_SECRET: ${SAT_HMAC_SECRET:-}
    volumes:
      - *templates_mount
    ports:
      - "8082:8080"
    depends_on:
      forge_opa_probe:
        condition: service_healthy
      forge_nats_probe:
        condition: service_healthy

  forge_orchestrator:
    <<: *app_defaults
    build:
      context: ./services/orchestrator
    image: forge_orchestrator:local
    container_name: forge_orchestrator
    environment:
      FORGE_ENV: dev
      TEMPLATE_DIR: /templates
      OPA_URL: http://forge_opa:8181
      NATS_URL: nats://forge_nats:4222
      SCOREBOARD_URL: http://forge_scoreboard:8080
      LOG_LEVEL: INFO
      SAT_HMAC_SECRET: ${SAT_HMAC_SECRET:-}
      ORCHESTRATOR_INTERNAL_TOKEN: ${ORCHESTRATOR_INTERNAL_TOKEN:-dev-internal}
      OPERATOR_TOKEN: ${OPERATOR_TOKEN:-dev-operator}
      SCOREBOARD_INTERNAL_TOKEN: ${SCOREBOARD_INTERNAL_TOKEN:-dev-scoreboard}
    networks:
      default:
        aliases:
          - orchestrator
          - orch
    volumes:
      - *templates_mount
    ports:
      - "8083:8080"
    depends_on:
      forge_opa_probe:
        condition: service_healthy
      forge_nats_probe:
        condition: service_healthy
      forge_scoreboard:
        condition: service_healthy

  forge_worker_agent:
    <<: *app_defaults
    build:
      context: ./services/worker_agent
    image: forge_worker_agent:local
    container_name: forge_worker_agent
    environment:
      FORGE_ENV: dev
      TEMPLATE_DIR: /templates
      NATS_URL: nats://forge_nats:4222
      MINIO_ENDPOINT: forge_minio:9000
      MINIO_ACCESS_KEY: ${MINIO_ROOT_USER:-forgeadmin}
      MINIO_SECRET_KEY: ${MINIO_ROOT_PASSWORD:-forgeadmin123}
      MINIO_BUCKET: forge-evidence
      LOG_LEVEL: INFO
    volumes:
      - *templates_mount
    ports:
      - "8084:8080"
    depends_on:
      forge_nats_probe:
        condition: service_healthy
      forge_minio:
        condition: service_started
      forge_minio_probe:
        condition: service_healthy

  forge_scoreboard:
    <<: *app_defaults
    build:
      context: ./services/scoreboard
    image: forge_scoreboard:local
    container_name: forge_scoreboard

    # dev: avoid the “volume owned by root, app runs as uid 1000” pain
    # staging/prod should NOT run as root; fix perms via initContainer/chown job instead.
    user: "0:0"

    environment:
      FORGE_ENV: dev
      NATS_URL: nats://forge_nats:4222
      MINIO_ENDPOINT: forge_minio:9000
      MINIO_ACCESS_KEY: ${MINIO_ROOT_USER:-forgeadmin}
      MINIO_SECRET_KEY: ${MINIO_ROOT_PASSWORD:-forgeadmin123}
      MINIO_BUCKET: forge-evidence
      LOG_LEVEL: INFO
      STORAGE_ROOT: /app/storage
      SCOREBOARD_INTERNAL_TOKEN: ${SCOREBOARD_INTERNAL_TOKEN:-dev-scoreboard}

    volumes:
      - forge_scoreboard_storage:/app/storage

    networks:
      default:
        aliases:
          - scoreboard

    ports:
      - "8086:8080"

    depends_on:
      forge_nats_probe:
        condition: service_healthy
      forge_minio:
        condition: service_started
      forge_minio_probe:
        condition: service_healthy

    # No wget/curl assumptions. Python is definitely present in your app image.
    healthcheck:
      test:
        [
          "CMD",
          "python",
          "-c",
          "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=2).read(); sys.exit(0)"
        ]
      interval: 10s
      timeout: 3s
      retries: 10
      start_period: 10s

  forge_observer_hub:
    <<: *app_defaults
    build:
      context: ./services/observer_hub
    image: forge_observer_hub:local
    container_name: forge_observer_hub
    environment:
      FORGE_ENV: dev
      NATS_URL: nats://forge_nats:4222
      LOKI_URL: http://forge_loki:3100
      LOG_LEVEL: INFO
    ports:
      - "8085:8080"
    depends_on:
      forge_nats_probe:
        condition: service_healthy
      forge_loki:
        condition: service_healthy

  forge_playbook_runner:
    <<: *app_defaults
    build:
      context: ./services/playbook_runner
    image: forge_playbook_runner:local
    container_name: forge_playbook_runner
    environment:
      FORGE_ENV: dev
      TEMPLATE_DIR: /templates
      PLAYBOOK_DIR: /playbooks
      LOG_LEVEL: INFO
    volumes:
      - *templates_mount
      - ./playbooks:/playbooks:ro
    ports:
      - "8087:8080"

  forge_metrics_tuner:
    <<: *app_defaults
    build:
      context: ./services/metrics_tuner
    image: forge_metrics_tuner:local
    container_name: forge_metrics_tuner
    environment:
      FORGE_ENV: dev
      NATS_URL: nats://forge_nats:4222
      REDIS_URL: redis://forge_redis:6379
      DEFAULT_QUOTA_SCENARIOS: "10"
      DEFAULT_QUOTA_WINDOW_HOURS: "24"
      ABUSE_THRESHOLD_RATE: "5.0"
      LOG_LEVEL: INFO
    ports:
      - "8088:8088"
    depends_on:
      forge_nats_probe:
        condition: service_healthy
      forge_redis:
        condition: service_healthy

  forge_egress_gateway:
    <<: *app_defaults
    build:
      context: ./services/egress_gateway
    image: forge_egress_gateway:local
    container_name: forge_egress_gateway
    environment:
      FORGE_ENV: dev
      NATS_URL: nats://forge_nats:4222
      DRY_RUN: "true"
      LOG_LEVEL: INFO
    ports:
      - "8089:8089"
    depends_on:
      forge_nats_probe:
        condition: service_healthy

  forge_llm_analyzer:
    <<: *app_defaults
    build:
      context: ./services/llm_analyzer
    image: forge_llm_analyzer:local
    container_name: forge_llm_analyzer
    environment:
      FORGE_ENV: dev
      NATS_URL: nats://forge_nats:4222
      OPA_URL: http://forge_opa:8181
      REDIS_URL: redis://forge_redis:6379
      CANARY_TIMEOUT_SECONDS: "30"
      LOG_LEVEL: INFO
    ports:
      - "8090:8090"
    depends_on:
      forge_nats_probe:
        condition: service_healthy
      forge_opa_probe:
        condition: service_healthy
      forge_redis:
        condition: service_healthy

  forge_overlay_sanitizer:
    <<: *app_defaults
    build:
      context: ./services/overlay_sanitizer
    image: forge_overlay_sanitizer:local
    container_name: forge_overlay_sanitizer
    environment:
      FORGE_ENV: dev
      NATS_URL: nats://forge_nats:4222
      MINIO_ENDPOINT: forge_minio:9000
      MINIO_ACCESS_KEY: ${MINIO_ROOT_USER:-forgeadmin}
      MINIO_SECRET_KEY: ${MINIO_ROOT_PASSWORD:-forgeadmin123}
      MINIO_BUCKET: forge-evidence
      SANITIZED_BUCKET: forge-sanitized
      LOG_LEVEL: INFO
    ports:
      - "8091:8091"
    depends_on:
      forge_nats_probe:
        condition: service_healthy
      forge_minio:
        condition: service_started
      forge_minio_probe:
        condition: service_healthy

  # ----------------------------
  # Infra services
  # ----------------------------

  forge_opa:
    <<: *infra_defaults
    image: openpolicyagent/opa:1.12.3
    container_name: forge_opa
    command:
      [
        "run",
        "--server",
        "--addr",
        "0.0.0.0:8181",
        "--ignore",
        ".*\\.bak_.*",
        "--ignore",
        ".*~",
        "--ignore",
        ".*\\.swp",
        "--ignore",
        ".*\\.tmp",
        "/policies"
      ]
    volumes:
      - ./policies:/policies:ro
    healthcheck:
      # Minimal health: binary exists. Real readiness is via forge_opa_probe.
      test: ["CMD", "/opa", "version"]
      interval: 10s
      timeout: 3s
      retries: 10
      start_period: 5s

  # Known-good health probe for OPA (curl is guaranteed here)
  forge_opa_probe:
    image: curlimages/curl:8.5.0
    container_name: forge_opa_probe
    command: ["sh", "-lc", "sleep infinity"]
    restart: unless-stopped
    depends_on:
      forge_opa:
        condition: service_started
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://forge_opa:8181/health?plugins >/dev/null || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 60
      start_period: 10s

  forge_redis:
    <<: *infra_defaults
    image: redis:7.2.4-alpine
    container_name: forge_redis
    command:
      [
        "redis-server",
        "--appendonly",
        "yes",
        "--maxmemory",
        "256mb",
        "--maxmemory-policy",
        "allkeys-lru"
      ]
    volumes:
      - forge_redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 10
      start_period: 5s

  forge_nats:
    <<: *infra_defaults
    image: nats:2.10-alpine
    container_name: forge_nats
    command: ["-js", "-sd", "/data", "-m", "8222"]
    volumes:
      - forge_nats_data:/data
    # Minimal health, real check via forge_nats_probe
    healthcheck:
      test: ["CMD", "true"]
      interval: 10s
      timeout: 2s
      retries: 3

  # Probe NATS via monitoring endpoint (curl guaranteed here)
  forge_nats_probe:
    image: curlimages/curl:8.5.0
    container_name: forge_nats_probe
    command: ["sh", "-lc", "sleep infinity"]
    restart: unless-stopped
    depends_on:
      forge_nats:
        condition: service_started
    network_mode: "service:forge_nats"
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:8222/varz >/dev/null || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 60
      start_period: 15s

  forge_minio:
    <<: *infra_defaults
    image: minio/minio:RELEASE.2024-01-16T16-07-38Z
    container_name: forge_minio
    command: ["server", "/data", "--address", ":9000", "--console-address", ":9001"]
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER:-forgeadmin}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:-forgeadmin123}
      MINIO_BROWSER: "off"
      MINIO_PROMETHEUS_AUTH_TYPE: "public"
    volumes:
      - forge_minio_data:/data
    stop_grace_period: 30s
    init: true
    healthcheck:
      test: ["NONE"]

  # Known-good health probe for MinIO (curl guaranteed; no DNS dependency)
  forge_minio_probe:
    image: curlimages/curl:8.5.0
    container_name: forge_minio_probe
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

  forge_loki:
    <<: *infra_defaults
    image: grafana/loki:2.9.4
    container_name: forge_loki
    command: ["-config.file=/etc/loki/local-config.yaml"]
    volumes:
      - forge_loki_data:/loki
    healthcheck:
      test: ["CMD", "true"]
      interval: 10s
      timeout: 2s
      retries: 3

  forge_prometheus:
    <<: *infra_defaults
    image: prom/prometheus:v2.49.1
    container_name: forge_prometheus
    command: ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus"]
    volumes:
      - ./telemetry/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - forge_prometheus_data:/prometheus

  forge_grafana:
    <<: *infra_defaults
    image: grafana/grafana:10.3.1
    container_name: forge_grafana
    environment:
      GF_SECURITY_ADMIN_USER: ${GRAFANA_USER:-forgeadmin}
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD:-forgeadmin}
    volumes:
      - ./telemetry/grafana/provisioning:/etc/grafana/provisioning:ro
      - forge_grafana_data:/var/lib/grafana

volumes:
  forge_scoreboard_storage:
  forge_redis_data:
  forge_minio_data:
  forge_loki_data:
  forge_prometheus_data:
  forge_grafana_data:
  forge_nats_data:

networks:
  default:
    name: forge_platform
    driver: bridge
YAML

echo "Wrote $OUT_COMPOSE"

echo "Validating compose file..."
docker compose -f "$OUT_COMPOSE" config >/dev/null

echo "Bringing stack up..."
docker compose -f "$OUT_COMPOSE" down -v
docker compose -f "$OUT_COMPOSE" up -d --build

echo
echo "Status:"
docker compose -f "$OUT_COMPOSE" ps

echo
echo "Unhealthy/restarting (if any):"
docker compose -f "$OUT_COMPOSE" ps | rg -n 'unhealthy|restarting' || echo "containers ok"

echo
echo "OPA health (inside network):"
docker compose -f "$OUT_COMPOSE" exec -T forge_opa_probe sh -lc 'curl -fsS http://forge_opa:8181/health?plugins | head -c 200; echo'

echo
echo "MinIO health (inside network):"
docker compose -f "$OUT_COMPOSE" exec -T forge_minio_probe sh -lc 'curl -fsS http://127.0.0.1:9000/minio/health/live; echo'

echo
echo "Spawn readyz:"
curl -fsS http://127.0.0.1:8082/readyz && echo
echo "Done."
