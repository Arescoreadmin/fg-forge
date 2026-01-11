#!/usr/bin/env bash
set -euo pipefail

NATS_URL=${NATS_URL:-nats://localhost:4222}

if ! command -v nats >/dev/null 2>&1; then
  echo "nats CLI not found. Install from https://github.com/nats-io/natscli" >&2
  exit 1
fi

nats --server "$NATS_URL" stream add forge-spawn --subjects "forge.spawn.*" --storage file --retention limits --max-msgs=-1 --max-bytes=-1 --max-age=0s --discard old --replicas 1 --no-deny-delete --no-deny-purge --force
nats --server "$NATS_URL" stream add forge-telemetry --subjects "forge.telemetry.*" --storage file --retention limits --max-msgs=-1 --max-bytes=-1 --max-age=0s --discard old --replicas 1 --no-deny-delete --no-deny-purge --force
