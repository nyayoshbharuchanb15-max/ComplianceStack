# SPDX-License-Identifier: Apache-2.0
"""Roles, scopes and service-account configuration (GOVERNANCE_AND_COMPLIANCE.md §3)."""
from __future__ import annotations
import os

PHASE_SCOPES = {
    "intake": "phase:intake",
    "scope": "phase:scope",
    "risk": "phase:risk",
    "data_protection": "phase:privacy",
    "fairness": "phase:fairness",
    "robustness": "phase:robustness",
    "explainability": "phase:explainability",
    "certification": "phase:certify",
    "monitoring": "phase:monitor",
}

ALL_SCOPES = sorted(set(PHASE_SCOPES.values()) |
                    {"reaudit:trigger", "runs:read", "certs:read", "certs:revoke"})

ROLE_SCOPES = {
    "governance-admin": ALL_SCOPES,
    "intake-officer": ["phase:intake", "phase:scope", "runs:read"],
    "audit-engineer": ["phase:risk", "phase:privacy", "phase:fairness",
                       "phase:robustness", "phase:explainability", "runs:read"],
    "certification-officer": ["phase:certify", "phase:monitor", "reaudit:trigger",
                              "runs:read", "certs:read", "certs:revoke"],
}


# Known-weak dev secrets that MUST NEVER be accepted in a live deployment.
# Startup will refuse to boot if any of these values is present in .env.
_FORBIDDEN_SECRET_VALUES = frozenset({
    "govern-admin-secret-dev", "intake-officer-secret-dev",
    "audit-engineer-secret-dev", "certification-officer-secret-dev",
    "governance-jwt-secret-dev", "changeme", "change-me", "dev", "test",
    "", "password", "secret",
})

_MIN_SECRET_LEN = 24  # ≥192 bits of entropy for HS256


class InsecureConfigError(RuntimeError):
    """Raised at startup when a required secret is unset or matches a known-dev value."""


def _require_strong_secret(env_key: str) -> str:
    value = os.environ.get(env_key)
    if value is None:
        raise InsecureConfigError(
            f"{env_key} is not set. Refusing to start with unset credentials.")
    if value in _FORBIDDEN_SECRET_VALUES:
        raise InsecureConfigError(
            f"{env_key} uses a known-weak default value. "
            "Generate a fresh 24+ character random string (e.g. "
            "`python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`) "
            "and set it in the deployment environment.")
    if len(value) < _MIN_SECRET_LEN:
        raise InsecureConfigError(
            f"{env_key} is shorter than {_MIN_SECRET_LEN} characters; "
            "rotate to a stronger secret.")
    return value


def service_accounts() -> dict[str, dict]:
    return {
        "governance-admin": {"secret": _require_strong_secret("GOV_ADMIN_SECRET"),
                             "role": "governance-admin"},
        "intake-officer": {"secret": _require_strong_secret("GOV_INTAKE_SECRET"),
                           "role": "intake-officer"},
        "audit-engineer": {"secret": _require_strong_secret("GOV_AUDIT_SECRET"),
                           "role": "audit-engineer"},
        "certification-officer": {"secret": _require_strong_secret("GOV_CERT_SECRET"),
                                  "role": "certification-officer"},
    }


def jwt_secret() -> str:
    return _require_strong_secret("GOVERNANCE_JWT_SECRET")


def token_ttl_minutes() -> int:
    return int(os.environ.get("GOVERNANCE_TOKEN_TTL_MINUTES", "60"))


def status_base_url() -> str:
    return os.environ.get("GOVERNANCE_PUBLIC_BASE_URL", "http://localhost:8010").rstrip("/")


def trusted_issuer_dids() -> list[str]:
    """Allow-list of did:key strings that the /verify route trusts as issuers.

    Empty list ⇒ trust ONLY the local signer (safe default). To trust
    additional signers (e.g. a federated compliance authority), set
    GOV_TRUSTED_ISSUER_DIDS to a comma-separated list of `did:key:z...`.
    """
    raw = os.environ.get("GOV_TRUSTED_ISSUER_DIDS", "")
    return [d.strip() for d in raw.split(",") if d.strip()]


def validate_startup_config() -> None:
    """Call once on FastAPI startup. Refuses to boot with weak/missing secrets."""
    service_accounts()
    jwt_secret()
