# forge_observer_hub

Telemetry aggregation layer for scenario events, audit logs, and fairness
metrics. Expected responsibilities:

- Consume telemetry topics from NATS (`forge.telemetry.*`).
- Normalize labels for Loki and Prometheus.
- Emit audit snapshots to MinIO.

Status: stub.
