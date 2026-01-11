#!/usr/bin/env bash
# FrostGate Forge - NATS JetStream setup script
set -euo pipefail

NATS_URL=${NATS_URL:-nats://localhost:4222}

echo "Setting up NATS JetStream streams..."

if ! command -v nats >/dev/null 2>&1; then
  echo "nats CLI not found. Install from https://github.com/nats-io/natscli" >&2
  echo "Alternatively, streams will be auto-created by services." >&2
  exit 0
fi

# Main Forge stream for spawn and scenario events
nats --server "$NATS_URL" stream add FORGE \
  --subjects "spawn.*,scenario.*" \
  --storage file \
  --retention limits \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --max-age=24h \
  --discard old \
  --replicas 1 \
  --no-deny-delete \
  --no-deny-purge \
  --force 2>/dev/null || echo "FORGE stream already exists or will be created by services"

# Telemetry stream for logs and metrics
nats --server "$NATS_URL" stream add TELEMETRY \
  --subjects "telemetry.*" \
  --storage file \
  --retention limits \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --max-age=1h \
  --discard old \
  --replicas 1 \
  --no-deny-delete \
  --no-deny-purge \
  --force 2>/dev/null || echo "TELEMETRY stream already exists or will be created by services"

# Audit stream for compliance events
nats --server "$NATS_URL" stream add AUDIT \
  --subjects "audit.*" \
  --storage file \
  --retention limits \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --max-age=30d \
  --discard old \
  --replicas 1 \
  --no-deny-delete \
  --no-deny-purge \
  --force 2>/dev/null || echo "AUDIT stream already exists or will be created by services"

echo "NATS JetStream streams configured."

# Show stream info
nats --server "$NATS_URL" stream ls 2>/dev/null || true
