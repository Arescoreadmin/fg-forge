# forge_metrics_tuner

Quota and fairness enforcement layer for the FrostGate Forge platform.

## Status: Implemented

## Features

- **Per-tenant quota tracking**: Track scenario usage against configurable quotas
- **Rate limiting**: Detect and prevent rapid-fire scenario spawning
- **Fairness alerts**: Emit warnings for potential abuse patterns
- **NATS integration**: Publish enforcement decisions to NATS streams
- **Blocking support**: Manually block/unblock tenants

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/v1/quota/check` | POST | Check quota for tenant |
| `/v1/quota/{tenant_id}` | GET | Get tenant quota config |
| `/v1/quota/{tenant_id}` | PUT | Update tenant quota config |
| `/v1/usage/{tenant_id}` | GET | Get tenant usage stats |
| `/v1/usage` | GET | List all tenant usage |
| `/v1/block/{tenant_id}` | POST | Block a tenant |
| `/v1/unblock/{tenant_id}` | POST | Unblock a tenant |
| `/v1/alerts` | GET | Get fairness alerts |
| `/v1/stats` | GET | Get aggregate statistics |

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NATS_URL` | `nats://forge_nats:4222` | NATS server URL |
| `REDIS_URL` | `redis://forge_redis:6379` | Redis URL (for persistence) |
| `DEFAULT_QUOTA_SCENARIOS` | `10` | Default scenarios per window |
| `DEFAULT_QUOTA_WINDOW_HOURS` | `24` | Quota window in hours |
| `ABUSE_THRESHOLD_RATE` | `5.0` | Spawns per minute threshold |

## NATS Streams

- Subscribes to: `quota.check`
- Publishes to: `quota.decision`

## Port

- Service runs on port `8088`
