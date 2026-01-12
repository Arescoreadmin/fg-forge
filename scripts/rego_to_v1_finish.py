#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re

POLICY_DIR = pathlib.Path("policies")

# Lines we should NOT touch:
# - assignments / data blocks like: foo := {  OR  foo = {
# - already converted lines containing: " if {"
IGNORE_IF_PRESENT = re.compile(r"\sif\s*\{\s*$")
IGNORE_DATA_BLOCK = re.compile(r"^\s*[\w.]+\s*(?::=|=)\s*\{\s*$")  # e.g. track_configs := {

# Partial set head: deny_reasons[msg] {
RE_PARTIAL_SET = re.compile(r"^(\s*)([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]\s*\{\s*$")

# Function head (allow spaces in RHS): f(x) = something with spaces {
RE_FUNC = re.compile(r"^(\s*)([A-Za-z_]\w*\s*\([^)]*\)\s*(?::=|=)\s*.+?)\s*\{\s*$")

# Normal rule head: allow {  or container_safe(x) {  or valid_actor {
RE_RULE = re.compile(r"^(\s*)([A-Za-z_]\w*(?:\s*\([^)]*\))?)\s*\{\s*$")

def convert_lines(lines: list[str]) -> tuple[list[str], bool]:
    out: list[str] = []
    changed = False

    for line in lines:
        if IGNORE_IF_PRESENT.search(line):
            out.append(line)
            continue
        if IGNORE_DATA_BLOCK.match(line):
            out.append(line)
            continue

        m = RE_PARTIAL_SET.match(line)
        if m and "=" not in line and ":=" not in line:
            indent, name, inner = m.groups()
            out.append(f"{indent}{name} contains {inner.strip()} if {{\n")
            changed = True
            continue

        m = RE_FUNC.match(line)
        if m:
            indent, head = m.groups()
            out.append(f"{indent}{head} if {{\n")
            changed = True
            continue

        m = RE_RULE.match(line)
        if m:
            indent, head = m.groups()
            out.append(f"{indent}{head} if {{\n")
            changed = True
            continue

        out.append(line)

    return out, changed

def main() -> int:
    changed_any = False
    for p in sorted(POLICY_DIR.glob("*.rego")):
        lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
        new_lines, changed = convert_lines(lines)
        if changed:
            p.write_text("".join(new_lines), encoding="utf-8")
        print(f"{p}: {'fixed' if changed else 'no-change'}")
        changed_any = changed_any or changed

    if not changed_any:
        print("No changes made on finish pass.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
