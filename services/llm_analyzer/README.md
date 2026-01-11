# forge_llm_analyzer

Governed LLM proposal pipeline with canary checks and rollback safety.

## Status: Implemented

## Features

- **Proposal analysis**: Validate proposed agent actions against safety rules
- **Signature verification**: Ed25519 signatures for proposal integrity
- **Canary execution**: Safe sandbox testing before approval
- **Policy class enforcement**: Risk-based validation (read_only → privileged)
- **Rollback support**: Automatic rollback on canary failure
- **OPA integration**: Policy decisions via OPA llm_gate

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/v1/proposals` | POST | Submit proposal for analysis |
| `/v1/proposals/{proposal_id}` | GET | Get proposal details |
| `/v1/proposals/{proposal_id}/result` | GET | Get analysis result |
| `/v1/proposals` | GET | List proposals |
| `/v1/stats` | GET | Get analyzer statistics |
| `/v1/policy-classes` | GET | List policy classes |
| `/v1/sign` | POST | Sign a proposal (dev) |
| `/v1/verify` | POST | Verify proposal signature |

## Policy Classes

| Class | Risk Level | Signature Required | Canary Required |
|-------|------------|-------------------|-----------------|
| `read_only` | Low | No | No |
| `write` | Medium | Yes | Yes |
| `execute` | High | Yes | Yes |
| `network` | High | Yes | Yes |
| `privileged` | Critical | Yes | Yes |

## Dangerous Action Detection

The analyzer blocks actions containing:
- Destructive patterns (`rm -rf /`, `dd if=/dev/zero`, etc.)
- Shell injection (`; rm`, `| rm`, `$(rm`, etc.)
- Fork bombs and system manipulation

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NATS_URL` | `nats://forge_nats:4222` | NATS server URL |
| `OPA_URL` | `http://forge_opa:8181` | OPA server URL |
| `REDIS_URL` | `redis://forge_redis:6379` | Redis URL |
| `CANARY_TIMEOUT_SECONDS` | `30` | Canary execution timeout |
| `MAX_PROPOSAL_SIZE` | `65536` | Max action content size |

## NATS Streams

- Subscribes to: `llm.proposal`
- Publishes to: `llm.decision`

## Port

- Service runs on port `8090`
