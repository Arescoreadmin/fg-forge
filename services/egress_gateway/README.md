# forge_egress_gateway

Egress gateway service enforcing deny-all by default with optional allowlist profiles.

## Status: Implemented

## Features

- **nftables-based network policy**: Apply per-scenario egress rules
- **Allowlist profiles**: Configurable profiles (none, training-updates, external-api, custom)
- **Audit logging**: Emit egress deny/allow logs to NATS
- **Dynamic policy management**: API to create/update/delete policies
- **Dry-run mode**: Test configurations without actual nftables changes

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/v1/policies` | GET | List all policies |
| `/v1/policies/{scenario_id}` | GET | Get policy for scenario |
| `/v1/policies` | POST | Create/update policy |
| `/v1/policies/{scenario_id}` | DELETE | Delete policy |
| `/v1/policies/{scenario_id}/enable` | POST | Enable policy |
| `/v1/policies/{scenario_id}/disable` | POST | Disable policy |
| `/v1/logs` | GET | Get egress logs |
| `/v1/stats` | GET | Get gateway statistics |
| `/v1/ruleset` | GET | Get current nftables ruleset |
| `/v1/profiles` | GET | List available profiles |

## Allowlist Profiles

- **none**: Strict deny-all (internal RFC1918 networks only)
- **training-updates**: Allow HTTP/HTTPS for package updates
- **external-api**: Allow HTTPS for external API access
- **custom**: Custom rules with explicit host/port allowlist

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NATS_URL` | `nats://forge_nats:4222` | NATS server URL |
| `NFT_BINARY` | `/usr/sbin/nft` | Path to nft binary |
| `DRY_RUN` | `true` | Enable dry-run mode |

## NATS Streams

- Subscribes to: `scenario.created`, `scenario.completed`
- Publishes to: `audit.egress`

## Port

- Service runs on port `8089`

## Note

For actual nftables enforcement, the container requires `NET_ADMIN` capability.
Set `DRY_RUN=false` when running with appropriate privileges.
