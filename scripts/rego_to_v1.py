#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import sys

POLICY_DIR = pathlib.Path("policies")

# Convert:
#   rule { ... }                  -> rule if { ... }
#   func(x) = y { ... }           -> func(x) = y if { ... }
#   func(x) := y { ... }          -> func(x) := y if { ... }
#
# Convert partial set:
#   set[x] { ... }                -> set contains x if { ... }
# (but do NOT touch object rules like obj[k] = v { ... })

RE_RULE_OPEN = re.compile(r"^(\s*)([A-Za-z_][\w]*(?:\[[^\]]+\])?)\s*\{\s*$")
RE_FUNC_OPEN = re.compile(r"^(\s*)([A-Za-z_][\w]*\s*\([^)]*\)\s*(?::=|=)\s*[^ {]+)\s*\{\s*$")
RE_OBJ_RULE_OPEN = re.compile(r"^(\s*)([A-Za-z_][\w]*\[[^\]]+\]\s*=\s*.+?)\s*\{\s*$")


def convert_line(line: str) -> str:
    # already v1
    if re.search(r"\sif\s*\{\s*$", line):
        return line

    # object rule like: obj[key] = val {
    if RE_OBJ_RULE_OPEN.match(line):
        indent, head = RE_OBJ_RULE_OPEN.match(line).groups()
        return f"{indent}{head} if {{\n"

    # function rule like: f(x) = y {
    if RE_FUNC_OPEN.match(line):
        indent, head = RE_FUNC_OPEN.match(line).groups()
        return f"{indent}{head} if {{\n"

    # simple rule or partial set like: deny[msg] {  OR  allowed[x] {
    m = RE_RULE_OPEN.match(line)
    if m:
        indent, head = m.groups()

        # partial set if head is like name[thing] (no '=' inside)
        if "[" in head and "]" in head and "=" not in head:
            name, inner = head.split("[", 1)
            inner = inner.rsplit("]", 1)[0].strip()
            # deny_reasons[msg] -> deny_reasons contains msg if {
            return f"{indent}{name} contains {inner} if {{\n"

        # boolean / array / object-less head: allow { -> allow if {
        return f"{indent}{head} if {{\n"

    return line


def convert_file(path: pathlib.Path) -> bool:
    original = path.read_text(encoding="utf-8").splitlines(keepends=True)
    converted = [convert_line(line) for line in original]
    if converted != original:
        path.write_text("".join(converted), encoding="utf-8")
        return True
    return False


def main() -> int:
    if not POLICY_DIR.exists():
        print("policies/ directory not found", file=sys.stderr)
        return 2

    changed_any = False
    for p in sorted(POLICY_DIR.glob("*.rego")):
        changed = convert_file(p)
        print(f"{p}: {'converted' if changed else 'no-change'}")
        changed_any = changed_any or changed

    if not changed_any:
        print("No changes made. Either already v1 or patterns didn't match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
