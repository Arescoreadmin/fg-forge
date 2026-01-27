#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FILES = {
    "compose": ROOT / "compose.yml",
    "staging": ROOT / "compose.staging.yml",
    "expose": ROOT / "compose.expose.yml",
    "env_staging": ROOT / ".env.staging",
    "env_prod": ROOT / "env.prod",
    "env_example": ROOT / ".env.example",
}

def read(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8")

def write(p: Path, s: str):
    p.write_text(s, encoding="utf-8")

def ensure_env_block_has_lines(text: str, svc: str, lines: list[str]) -> str:
    """
    Insert environment lines under services.<svc>.environment: respecting indentation.
    Idempotent: won't duplicate keys if already present.
    """
    # Find the service block
    # crude but stable given your compose formatting
    svc_pat = rf"(?ms)^  {re.escape(svc)}:\n(.*?)(?=^  [a-zA-Z0-9_]+:\n|\Z)"
    m = re.search(svc_pat, text)
    if not m:
        raise RuntimeError(f"service '{svc}' not found")

    svc_block = m.group(0)

    # Find environment block inside service
    env_pat = r"(?ms)^(\s+environment:\n)(.*?)(?=^\s+(volumes|depends_on|ports|networks|healthcheck|command|user|group_add|profiles|restart|image|build):|\Z)"
    em = re.search(env_pat, svc_block)
    if not em:
        # No environment block: add one after container_name or image/build
        insert_after_pat = r"(?m)^\s+container_name:.*\n"
        im = re.search(insert_after_pat, svc_block)
        if not im:
            # fallback: after service header line
            header_pat = rf"(?m)^  {re.escape(svc)}:\n"
            im = re.search(header_pat, svc_block)
        indent = "    "
        env_lines = indent + "environment:\n" + "".join([indent + "  " + l + "\n" for l in lines])
        if im:
            insert_at = im.end()
            new_block = svc_block[:insert_at] + env_lines + svc_block[insert_at:]
        else:
            new_block = svc_block + "\n" + env_lines
    else:
        env_header = em.group(1)
        env_body = em.group(2)
        # Determine indent for env entries (your file uses 6 spaces before keys)
        # Example: "      FORGE_ENV: ..."
        entry_indent = re.search(r"(?m)^(\s+)\S", env_body)
        entry_indent = entry_indent.group(1) if entry_indent else "      "

        # Build existing keys set
        existing_keys = set(re.findall(r"(?m)^\s*([A-Z0-9_]+)\s*:", env_body))

        add_lines = []
        for l in lines:
            k = l.split(":", 1)[0].strip()
            if k in existing_keys:
                continue
            add_lines.append(entry_indent + l + "\n")

        if add_lines:
            # append at end of env block
            new_env_body = env_body + "".join(add_lines)
            new_block = svc_block.replace(env_header + env_body, env_header + new_env_body, 1)
        else:
            new_block = svc_block

    return text.replace(svc_block, new_block, 1)

def ensure_env_file_has_kv(text: str, kv_lines: list[str]) -> str:
    existing = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        existing.add(line.split("=", 1)[0].strip())

    out = text.rstrip("\n")
    if out and not out.endswith("\n"):
        out += "\n"

    for kv in kv_lines:
        k = kv.split("=", 1)[0].strip()
        if k in existing:
            continue
        out += kv.rstrip() + "\n"

    return out

def ensure_staging_requires(text: str, svc: str, required_keys: list[str]) -> str:
    """
    In compose.staging.yml, under services.<svc>.environment, ensure VAR: ${VAR:?required}
    Idempotent: if VAR is present, leave it.
    """
    lines = [f"{k}: ${{{k}:?required}}" for k in required_keys]
    return ensure_env_block_has_lines(text, svc, lines)

def ensure_expose_gateway_port(text: str) -> str:
    # You already have forge_egress_gateway -> 8089:8080.
    # Make sure it exists; if not, insert it.
    if re.search(r"(?m)^\s*forge_egress_gateway:\s*\n", text) and re.search(r"(?m)^\s*forge_egress_gateway:\s*\n(?:.*\n)*?\s*ports:\s*\n(?:.*\n)*?\s*-\s*\"8089:8080\"\s*$", text):
        return text

    if re.search(r"(?m)^\s*forge_egress_gateway:\s*$", text):
        # service exists but port mapping missing, add under it
        return re.sub(
            r"(?ms)^(\s*forge_egress_gateway:\s*\n)(.*?)(?=^\S|\Z)",
            lambda m: m.group(1) + m.group(2) + ("\n  ports:\n    - \"8089:8080\"\n" if "ports:" not in m.group(0) else ""),
            text,
            count=1,
        )

    # service missing; add minimal entry
    add = '\n  forge_egress_gateway:\n    ports:\n      - "8089:8080"\n'
    return text.rstrip("\n") + add + "\n"

def main():
    compose = read(FILES["compose"])
    staging = read(FILES["staging"])
    expose = read(FILES["expose"])

    if not compose:
        raise RuntimeError("compose.yml not found or empty")

    # --- Patch compose.yml ---
    # Spawn service needs public gateway base + cap token mint secret
    compose = ensure_env_block_has_lines(
        compose,
        "forge_spawn_service",
        [
            # Spawn issues capability URLs to the gateway
            "EGRESS_GATEWAY_PUBLIC_URL: ${EGRESS_GATEWAY_PUBLIC_URL:-http://localhost:8089}",
            "CAP_TOKEN_SECRET: ${CAP_TOKEN_SECRET:-dev-cap-secret-change-me}",
            "CAP_TOKEN_TTL_SECONDS: ${CAP_TOKEN_TTL_SECONDS:-300}",
        ],
    )

    # Gateway becomes the capability broker (Option C)
    compose = ensure_env_block_has_lines(
        compose,
        "forge_egress_gateway",
        [
            # Required for cap validation
            "CAP_TOKEN_SECRET: ${CAP_TOKEN_SECRET:-dev-cap-secret-change-me}",
            # OPA access gate (separate from your existing OPA_URL usage elsewhere)
            "OPA_URL: ${OPA_URL:-http://forge_opa:8181}",
            # Session controls
            "TTY_IDLE_SECONDS: ${TTY_IDLE_SECONDS:-900}",
            "TTY_MAX_SECONDS: ${TTY_MAX_SECONDS:-1800}",
            # If you want SAT enforced at the gateway
            "SAT_REQUIRED: ${SAT_REQUIRED:-false}",
            # Optional: single-use caps
            "CAP_SINGLE_USE: ${CAP_SINGLE_USE:-false}",
            "REDIS_URL: ${REDIS_URL:-redis://forge_redis:6379}",
        ],
    )

    # --- Patch compose.staging.yml ---
    if staging:
        staging = ensure_staging_requires(staging, "forge_spawn_service", ["CAP_TOKEN_SECRET", "EGRESS_GATEWAY_PUBLIC_URL"])
        staging = ensure_staging_requires(staging, "forge_egress_gateway", ["CAP_TOKEN_SECRET"])
    else:
        print("WARN: compose.staging.yml missing; skipping staging patches")

    # --- Patch compose.expose.yml ---
    if expose:
        expose = ensure_expose_gateway_port(expose)
    else:
        print("WARN: compose.expose.yml missing; skipping expose patch")

    # --- Patch env files ---
    env_staging = read(FILES["env_staging"])
    env_prod = read(FILES["env_prod"])
    env_example = read(FILES["env_example"])

    if env_staging:
        env_staging = ensure_env_file_has_kv(env_staging, [
            "EGRESS_GATEWAY_PUBLIC_URL=https://staging.yourdomain.tld",
            "CAP_TOKEN_SECRET=REPLACE_ME",
            "CAP_TOKEN_TTL_SECONDS=300",
            "TTY_IDLE_SECONDS=900",
            "TTY_MAX_SECONDS=1800",
            "SAT_REQUIRED=false",
            "CAP_SINGLE_USE=false",
        ])

    if env_prod:
        env_prod = ensure_env_file_has_kv(env_prod, [
            "EGRESS_GATEWAY_PUBLIC_URL=https://YOUR_DOMAIN",
            "CAP_TOKEN_SECRET=REPLACE_ME",
            "CAP_TOKEN_TTL_SECONDS=300",
            "TTY_IDLE_SECONDS=900",
            "TTY_MAX_SECONDS=1800",
            "SAT_REQUIRED=true",
            "CAP_SINGLE_USE=true",
        ])

    if env_example:
        env_example = ensure_env_file_has_kv(env_example, [
            "",
            "# --- Gateway-only access (Option C) ---",
            "EGRESS_GATEWAY_PUBLIC_URL=http://localhost:8089",
            "CAP_TOKEN_SECRET=change-me-long-random",
            "CAP_TOKEN_TTL_SECONDS=300",
            "TTY_IDLE_SECONDS=900",
            "TTY_MAX_SECONDS=1800",
            "SAT_REQUIRED=false",
            "CAP_SINGLE_USE=false",
        ])

    # Write back
    write(FILES["compose"], compose)
    if staging:
        write(FILES["staging"], staging)
    if expose:
        write(FILES["expose"], expose)
    if env_staging:
        write(FILES["env_staging"], env_staging)
    if env_prod:
        write(FILES["env_prod"], env_prod)
    if env_example:
        write(FILES["env_example"], env_example)

    print("OK: patched compose + env files for gateway-only access (Option C).")
    print("Next: wire spawn_service /v1/access/{sid} to mint cap URLs using EGRESS_GATEWAY_PUBLIC_URL.")

if __name__ == "__main__":
    main()
