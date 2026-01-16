#!/usr/bin/env python3
"""
Patch compose.yml / compose.staging.yml:
- Add seccomp + no-new-privileges to security_opt for all services
- Remove docker.sock mounts except allowlist services (default: orchestrator)
- Backup files before writing

Usage:
  python3 tools/patch_compose_hardening.py --apply
  python3 tools/patch_compose_hardening.py --apply --allow-docker-sock orchestrator,worker_agent
  python3 tools/patch_compose_hardening.py --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml  # PyYAML
except Exception:
    print("ERROR: PyYAML not installed. Install with: pip install pyyaml", file=sys.stderr)
    raise

COMPOSE_FILES_DEFAULT = ["compose.yml", "compose.staging.yml"]

DEFAULT_SECCOMP = "seccomp:default"  # If this doesn't work in your Compose version, use a file profile instead.

def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_yaml(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a YAML mapping at top level")
    return data

def dump_yaml(data: Dict[str, Any]) -> str:
    # Note: This will not preserve comments/ordering perfectly (PyYAML limitation).
    # It will preserve structure and be valid.
    return yaml.safe_dump(
        data,
        sort_keys=False,
        default_flow_style=False,
    )

def ensure_security_opt(service: Dict[str, Any], seccomp_value: str) -> bool:
    """
    Ensure:
      security_opt includes "no-new-privileges:true"
      security_opt includes seccomp_value (e.g., "seccomp:default")
    Return True if changed.
    """
    changed = False
    secopt = service.get("security_opt")

    if secopt is None:
        service["security_opt"] = ["no-new-privileges:true", seccomp_value]
        return True

    if isinstance(secopt, str):
        # Normalize to list
        secopt_list = [secopt]
    elif isinstance(secopt, list):
        secopt_list = list(secopt)
    else:
        # Unknown type, bail loudly
        raise ValueError(f"security_opt must be list or string, got: {type(secopt)}")

    def has_prefix(prefix: str) -> bool:
        return any(isinstance(x, str) and x.strip().startswith(prefix) for x in secopt_list)

    if not has_prefix("no-new-privileges"):
        secopt_list.append("no-new-privileges:true")
        changed = True

    if not has_prefix("seccomp:"):
        secopt_list.append(seccomp_value)
        changed = True

    service["security_opt"] = secopt_list
    return changed

def remove_docker_sock_mounts(service: Dict[str, Any]) -> bool:
    """
    Remove any volume mounts containing /var/run/docker.sock
    Return True if changed.
    """
    vols = service.get("volumes")
    if not vols:
        return False

    if not isinstance(vols, list):
        # Some people do weird YAML. We won't guess.
        raise ValueError(f"volumes must be a list, got: {type(vols)}")

    before = len(vols)
    after_list: List[Any] = []
    for v in vols:
        if isinstance(v, str) and "/var/run/docker.sock" in v:
            continue
        after_list.append(v)

    if len(after_list) != before:
        service["volumes"] = after_list
        return True
    return False

def patch_compose(compose_path: Path, allow_docker_sock: set[str], seccomp_value: str) -> Dict[str, Any]:
    data = load_yaml(compose_path)
    services = data.get("services")
    if not isinstance(services, dict):
        raise ValueError(f"{compose_path}: missing or invalid 'services' mapping")

    changed_any = False
    changes: Dict[str, Any] = {"file": str(compose_path), "services_changed": []}

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        svc_changed = False

        # security_opt patch for every service
        if ensure_security_opt(svc_def, seccomp_value):
            svc_changed = True

        # docker.sock removal unless allowlisted
        if svc_name not in allow_docker_sock:
            if remove_docker_sock_mounts(svc_def):
                svc_changed = True

        if svc_changed:
            changed_any = True
            changes["services_changed"].append(svc_name)

    changes["changed"] = changed_any
    changes["data"] = data
    return changes

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write changes to files (default is dry-run).")
    ap.add_argument("--dry-run", action="store_true", help="Show what would change without writing.")
    ap.add_argument("--files", default=",".join(COMPOSE_FILES_DEFAULT), help="Comma-separated compose files to patch.")
    ap.add_argument("--allow-docker-sock", default="orchestrator", help="Comma-separated service names allowed to keep docker.sock.")
    ap.add_argument("--seccomp", default=DEFAULT_SECCOMP, help="Seccomp setting to add (e.g., seccomp:default or seccomp:docker/seccomp.json).")
    args = ap.parse_args()

    if args.dry_run and args.apply:
        print("Pick one: --dry-run OR --apply", file=sys.stderr)
        return 2

    apply = args.apply
    files = [f.strip() for f in args.files.split(",") if f.strip()]
    allow = {s.strip() for s in args.allow_docker_sock.split(",") if s.strip()}
    seccomp_value = args.seccomp.strip()

    report = []
    for f in files:
        path = Path(f)
        if not path.exists():
            print(f"SKIP: {f} not found")
            continue

        patched = patch_compose(path, allow, seccomp_value)
        changed = patched["changed"]
        services_changed = patched["services_changed"]

        report.append((str(path), changed, services_changed))

        if not changed:
            continue

        if apply:
            backup = path.with_suffix(path.suffix + f".bak_{now_stamp()}")
            backup.write_text(path.read_text())
            path.write_text(dump_yaml(patched["data"]))
            print(f"WROTE: {path} (backup: {backup})")
        else:
            print(f"WOULD CHANGE: {path}")
            for s in services_changed:
                print(f"  - {s}")

    # Summary
    print("\nSummary:")
    for path, changed, services_changed in report:
        if changed:
            print(f"  {path}: changed ({len(services_changed)} services)")
        else:
            print(f"  {path}: no changes")

    if not apply:
        print("\nDry-run complete. Re-run with --apply to write changes.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
