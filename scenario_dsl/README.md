# Scenario DSL

Scenario definitions live in `templates/` as YAML and must be immutable at runtime.
The orchestrator is responsible for validating scenarios against OPA and enforcing
network isolation, resource budgets, and success criteria.
