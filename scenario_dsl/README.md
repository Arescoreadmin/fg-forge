# Scenario DSL

Scenario definitions live in `templates/` as YAML and must be immutable at runtime.
The orchestrator is responsible for validating scenarios against OPA and enforcing
network isolation, resource budgets, and success criteria.

## Template Fields

Required blocks:
- `metadata.labels`: track + tier labels used by OPA
- `limits`: resource budgets and adversary constraints
- `network`: egress policy and allowlist profile
- `assets`: containers, services, datasets
- `successCriteria`: evidence contract for scoring

## Scoring Contract

Automated grading must emit the following artifacts for each scenario run:

- `score.json` (normalized scores)
- `evidence.tar.zst` (artifacts + telemetry excerpts)
- `verdict.sig` (signature over hashes)

The scoreboard service owns deterministic aggregation and signing.
