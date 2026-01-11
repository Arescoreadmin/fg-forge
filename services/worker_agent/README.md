# forge_worker_agent

Scenario worker that executes deterministic playbooks, gathers evidence, and
uploads artifacts for scoring. Expected responsibilities:

- Fetch scenario assignment from NATS (`forge.spawn.assigned`).
- Run playbooks via `forge_playbook_runner`.
- Collect evidence artifacts and telemetry excerpts.
- Upload evidence bundles to MinIO.

Status: stub.
