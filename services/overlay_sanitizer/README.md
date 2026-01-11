# forge_overlay_sanitizer

PII scrubbing and audit sanitization service for compliance exports.

## Status: Implemented

## Features

- **PII detection**: Identify emails, SSNs, credit cards, IPs, API keys, passwords
- **Configurable sanitization levels**: Minimal, standard, strict
- **Allowlist preservation**: Keep internal identifiers and scenario data
- **Signed audit bundles**: Ed25519 signatures for tamper detection
- **MinIO integration**: Store sanitized artifacts and bundles
- **NATS events**: Async sanitization via message queue

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/v1/sanitize` | POST | Sanitize scenario evidence |
| `/v1/sanitize/text` | POST | Sanitize text (testing) |
| `/v1/results/{request_id}` | GET | Get sanitization result |
| `/v1/results` | GET | List results |
| `/v1/bundles/{scenario_id}` | POST | Create audit bundle |
| `/v1/bundles/{bundle_id}` | GET | Get bundle details |
| `/v1/bundles/{bundle_id}/download` | GET | Download bundle ZIP |
| `/v1/bundles` | GET | List bundles |
| `/v1/stats` | GET | Get sanitizer statistics |
| `/v1/pii-types` | GET | List supported PII types |

## Sanitization Levels

| Level | Description |
|-------|-------------|
| `minimal` | Only obvious PII (SSN, credit cards, passwords) |
| `standard` | PII + internal identifiers |
| `strict` | All potentially sensitive data |

## PII Types Detected

- `email`: Email addresses
- `ssn`: Social Security Numbers
- `credit_card`: Credit card numbers
- `phone`: Phone numbers
- `ip_address`: IP addresses (external)
- `api_key`: API keys and secrets
- `password`: Password values

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NATS_URL` | `nats://forge_nats:4222` | NATS server URL |
| `MINIO_ENDPOINT` | `forge_minio:9000` | MinIO endpoint |
| `MINIO_ACCESS_KEY` | `forgeadmin` | MinIO access key |
| `MINIO_SECRET_KEY` | `forgeadmin123` | MinIO secret key |
| `MINIO_BUCKET` | `forge-evidence` | Source bucket |
| `SANITIZED_BUCKET` | `forge-sanitized` | Sanitized output bucket |

## NATS Streams

- Subscribes to: `sanitization.request`
- Publishes to: `sanitization.completed`

## Port

- Service runs on port `8091`
