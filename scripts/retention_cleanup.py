#!/usr/bin/env python3
"""Retention cleanup for stored scenario artifacts."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hmac
import os
from pathlib import Path
import shutil

INVESTIGATION_FLAG = "investigation.flag"


@dataclass(frozen=True)
class CleanupTarget:
    scenario_id: str
    results_dir: Path
    updated_at: datetime


def _require_operator_token(provided: str | None) -> None:
    expected = os.getenv("OPERATOR_TOKEN")
    if not expected:
        raise PermissionError("OPERATOR_TOKEN not configured")
    if not provided or not hmac.compare_digest(provided, expected):
        raise PermissionError("operator auth required")


def _scenario_dirs(storage_root: Path) -> list[Path]:
    scenarios_dir = storage_root / "scenarios"
    if not scenarios_dir.exists():
        return []
    return sorted([p for p in scenarios_dir.iterdir() if p.is_dir()])


def _has_investigation_flag(scenario_dir: Path) -> bool:
    return (scenario_dir / INVESTIGATION_FLAG).exists()


def _results_dir(scenario_dir: Path) -> Path:
    return scenario_dir / "results"


def find_expired_results(
    storage_root: Path, retention_days: int, now: datetime | None = None
) -> list[CleanupTarget]:
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)
    targets: list[CleanupTarget] = []
    for scenario_dir in _scenario_dirs(storage_root):
        if _has_investigation_flag(scenario_dir):
            continue
        results_dir = _results_dir(scenario_dir)
        if not results_dir.is_dir():
            continue
        mtime = datetime.fromtimestamp(results_dir.stat().st_mtime, tz=UTC)
        if mtime <= cutoff:
            targets.append(
                CleanupTarget(
                    scenario_id=scenario_dir.name,
                    results_dir=results_dir,
                    updated_at=mtime,
                )
            )
    targets.sort(key=lambda target: target.scenario_id)
    return targets


def perform_cleanup(targets: list[CleanupTarget], dry_run: bool) -> list[str]:
    log_lines: list[str] = []
    for target in targets:
        if dry_run:
            log_lines.append(f"DRY-RUN delete {target.results_dir}")
            continue
        shutil.rmtree(target.results_dir)
        log_lines.append(f"DELETE {target.results_dir}")
    return log_lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Cleanup expired artifacts.")
    parser.add_argument(
        "--storage-root",
        type=Path,
        default=Path(os.getenv("STORAGE_ROOT", "storage")),
        help="Root storage directory",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=int(os.getenv("RETENTION_DAYS", "30")),
        help="Retention window in days",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List deletions without removing data",
    )
    parser.add_argument(
        "--operator-token",
        type=str,
        default=None,
        help="Operator token for authorization",
    )
    args = parser.parse_args()

    try:
        _require_operator_token(args.operator_token)
    except PermissionError as exc:
        print(f"FAIL: {exc}")
        return 1

    targets = find_expired_results(args.storage_root, args.retention_days)
    logs = perform_cleanup(targets, args.dry_run)
    for line in logs:
        print(line)
    print(f"CLEANUP complete: {len(logs)} deleted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
