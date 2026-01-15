#!/usr/bin/env bash
set -euo pipefail
trap 'rc=$?; echo; echo "❌ Failed at line $LINENO: $BASH_COMMAND"; echo "exit=$rc"; exit $rc' ERR

cd /home/jcosat/Projects/fg-forge
source .venv/bin/activate
export PYTHONPATH="."

echo "== ruff =="
ruff check . --output-format=github

echo "== compileall =="
python -m compileall -q services scripts

echo "== import smoke =="
python -c "import services.spawn_service.app.main as m; assert hasattr(m, 'app')"
python -c "import services.orchestrator.app.main as m; assert hasattr(m, 'app')"
python -c "import services.scoreboard.app.main as m; assert hasattr(m, 'app')"

echo "== secret scan =="
PATTERN='BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'

# NOTE: rg exit code 1 means "no matches" (fine). With set -e, wrap it in if.
if rg -n --hidden --no-ignore-vcs \
  --glob '!.git/**' \
  --glob '!.venv/**' \
  --glob '!venv/**' \
  --glob '!**/__pycache__/**' \
  --glob '!**/*.pyc' \
  --glob '!node_modules/**' \
  --glob '!dist/**' \
  --glob '!build/**' \
  --glob '!storage/**' \
  "$PATTERN" .; then
  echo "Potential secret material detected."
  exit 1
fi
echo "✅ secret scan clean"

echo "== pip-audit =="
# If you want strict mode: delete IGNORE_ARGS and bump deps instead of ignoring CVEs.
IGNORE_ARGS=(
  "--ignore-vuln" "PYSEC-2024-38"
  "--ignore-vuln" "CVE-2024-35195"
  "--ignore-vuln" "CVE-2024-47081"
  "--ignore-vuln" "CVE-2024-47881"
  "--ignore-vuln" "CVE-2025-54121"
  "--ignore-vuln" "CVE-2024-47874"
)

pip-audit -r services/spawn_service/requirements.txt "${IGNORE_ARGS[@]}"
pip-audit -r services/orchestrator/requirements.txt "${IGNORE_ARGS[@]}"
pip-audit -r services/scoreboard/requirements.txt "${IGNORE_ARGS[@]}"
if [ -f scripts/requirements.txt ]; then
  pip-audit -r scripts/requirements.txt "${IGNORE_ARGS[@]}"
fi
echo "✅ pip-audit ok (with ignores)"

echo "== OPA policy tests (Rego v1) =="
if command -v docker >/dev/null 2>&1; then
  if rg -n --hidden --no-ignore-vcs '(^\s*docker\b.*\bopa\b.*\btest\b.*--v1\b|\bopa\s+test\b.*--v1\b)' .github/workflows policies; then
    echo "ERROR: '--v1' flag detected in opa test command."
    exit 1
  fi

  OPA_IMAGE="openpolicyagent/opa@sha256:c0609fecc0924743f8648dc4a035d2f57ca163dc723ed1d13f3197ba5bd122b3"
  docker pull "$OPA_IMAGE" >/dev/null
  opa() { docker run --rm -v "$PWD:/workspace" -w /workspace "$OPA_IMAGE" "$@"; }

  opa version
  opa fmt --fail policies/
  opa test -v policies/
  echo "✅ opa ok"
else
  echo "⚠️  docker not available locally, skipping OPA (CI will run it)"
fi

echo "== unit tests (spawn_service) =="
python -m unittest discover -s services/spawn_service/tests -v

echo "== unit tests (orchestrator) =="
export UNIT_TESTS=1
export ORCHESTRATOR_INTERNAL_TOKEN=test-internal
export OPERATOR_TOKEN=test-operator
export SCOREBOARD_INTERNAL_TOKEN=test-scoreboard
export SCOREBOARD_ASGI_IMPORT=services.scoreboard.app.main:app
python -m unittest discover -s services/orchestrator/tests -v

echo "== unit tests (scoreboard) =="
python -m unittest discover -s services/scoreboard/tests -v

echo "== unit tests (scripts) =="
python -m unittest discover -s scripts/tests -v

echo "✅ CI local pass"
