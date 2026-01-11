# forge_orchestrator

Scenario orchestrator responsible for validating templates, enforcing OPA gates,
and launching isolated scenario networks. It should:

- Load immutable templates from `/templates`.
- Call OPA (`/v1/data/frostgate/forge/training/allow`) before any spawn.
- Create per-scenario networks and apply egress profiles.
- Emit spawn lifecycle events to NATS (`forge.spawn.*`).
- Record audit metadata for downstream scoring.

Status: stub.
