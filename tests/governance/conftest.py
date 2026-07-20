"""Shared pytest fixtures — read service-account secrets from env vars.

The orchestrator refuses to boot with the previously-committed dev secrets,
so tests must source them the same way the orchestrator does. Reads
`/app/backend/.env` if the variable isn't already in the process env.
"""
from __future__ import annotations
import os
from pathlib import Path


def _seed_from_env_file() -> None:
    env_path = Path("/app/backend/.env")
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


_seed_from_env_file()


def _secret(env_var: str) -> str:
    v = os.environ.get(env_var, "")
    if not v:
        raise RuntimeError(
            f"{env_var} not set — cannot run governance test suite. "
            "Set it in /app/backend/.env or export it.")
    return v


# Centralised credential map used by every test module.
CREDS = {
    "governance-admin": _secret("GOV_ADMIN_SECRET"),
    "intake-officer": _secret("GOV_INTAKE_SECRET"),
    "audit-engineer": _secret("GOV_AUDIT_SECRET"),
    "certification-officer": _secret("GOV_CERT_SECRET"),
}
