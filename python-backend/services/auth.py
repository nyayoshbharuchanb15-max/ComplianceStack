"""
Authentication & Authorization Service — OAuth 2.1 + RBAC + RS256
──────────────────────────────────────────────────────────────────
Provides RS256-signed JWT-based authentication with role-based access
control (RBAC) and scoped endpoint filtering for the AI Governance API.

OAuth 2.1 (RFC 6749, updated) patterns:
  - Bearer token authentication (Authorization header)
  - Scoped access tokens (audit:read, audit:write, admin:all)
  - Token introspection endpoint (RFC 7662)
  - Refresh token rotation
  - PKCE for authorization code flow (S256)
  - State parameter validation

Roles:
  - admin:   Full access to all endpoints and configuration
  - auditor: Execute audit phases, view results
  - viewer:  Read-only access to audit results and certificates

Security:
  - RS256-signed JWTs with loaded RSA private key
  - Token expiry configurable via env var
  - Scoped permission checks on every protected endpoint
  - Ephemeral fallback key for development (logs warning)
"""

from __future__ import annotations
import base64
import hashlib
import os
import secrets
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

from services.key_provider import EnvironmentKeyProvider, KeyNotFoundError

# ─── RSA Key Loading ──────────────────────────────────────────────
# Key resolution order:
#   1. AUTH_PRIVATE_KEY_PATH   — path to PEM file on disk
#   2. AUTH_PRIVATE_KEY        — PEM-encoded key as environment variable
#   3. Ephemeral generated key — development only (logs warning)
#
# For production, configure a key via environment variables or use a
# custom BaseKeyProvider implementation (see services/key_provider.py).

_AUTH_KEY_PROVIDER = EnvironmentKeyProvider(
    env_var="AUTH_PRIVATE_KEY",
    path_var="AUTH_PRIVATE_KEY_PATH",
)

PRODUCTION_MODE = os.environ.get("PRODUCTION_MODE", "false").lower() in ("1", "true", "yes")

try:
    _private_key_pem: bytes = _AUTH_KEY_PROVIDER.get_private_key()
except KeyNotFoundError:
    if PRODUCTION_MODE:
        raise RuntimeError(
            "╔══════════════════════════════════════════════════════════════════╗\n"
            "║  FATAL: PRODUCTION MODE requires AUTH_PRIVATE_KEY or             ║\n"
            "║  AUTH_PRIVATE_KEY_PATH to be set. Ephemeral keys are not        ║\n"
            "║  permitted in production.                                       ║\n"
            "║                                                                 ║\n"
            "║  Generate a key pair:                                           ║\n"
            "║    openssl genrsa -out private.pem 2048                         ║\n"
            "║    openssl rsa -in private.pem -pubout -out public.pem          ║\n"
            "║                                                                 ║\n"
            "║  Set environment variables:                                     ║\n"
            "║    AUTH_PRIVATE_KEY=<PEM contents>                              ║\n"
            "║    or AUTH_PRIVATE_KEY_PATH=/path/to/private.pem                ║\n"
            "╚══════════════════════════════════════════════════════════════════╝"
        )
    warnings.warn(
        "╔══════════════════════════════════════════════════════════════════╗\n"
        "║  WARNING: EPHEMERAL RSA KEY — NOT FOR PRODUCTION                ║\n"
        "║  No AUTH_PRIVATE_KEY or AUTH_PRIVATE_KEY_PATH set.              ║\n"
        "║  Using ephemeral 2048-bit RSA key.                              ║\n"
        "║  Every restart invalidates previously issued JWTs.              ║\n"
        "║  Generate a key pair for production:                            ║\n"
        "║    openssl genrsa -out private.pem 2048                         ║\n"
        "║    openssl rsa -in private.pem -pubout -out public.pem          ║\n"
        "╚══════════════════════════════════════════════════════════════════╝"
    )
    _ephemeral_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    _private_key_pem = _ephemeral_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

_PRIVATE_KEY = serialization.load_pem_private_key(_private_key_pem, password=None)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
ALGORITHM = "RS256"

# ─── Configuration ────────────────────────────────────────────────

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("AUTH_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("AUTH_REFRESH_EXPIRE_DAYS", "7"))
DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() in ("1", "true", "yes")


class Role(str, Enum):
    admin = "admin"
    auditor = "auditor"
    viewer = "viewer"


class Scope(str, Enum):
    audit_read = "audit:read"
    audit_write = "audit:write"
    audit_all = "audit:all"
    admin_all = "admin:all"


# ─── Role → Scope Mapping ─────────────────────────────────────────

ROLE_SCOPES: dict[Role, list[Scope]] = {
    Role.viewer: [Scope.audit_read],
    Role.auditor: [Scope.audit_read, Scope.audit_write],
    Role.admin: [Scope.audit_read, Scope.audit_write, Scope.audit_all, Scope.admin_all],
}


# ─── PKCE Helpers ─────────────────────────────────────────────────


def generate_code_verifier() -> str:
    """Generate a PKCE code verifier (43–128 url-safe chars)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()


def generate_code_challenge(verifier: str) -> str:
    """Generate an S256 PKCE code challenge from a verifier."""
    return base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()
    ).rstrip(b"=").decode()


def generate_state() -> str:
    """Generate a random state parameter for CSRF protection."""
    return secrets.token_hex(32)


# ─── Token Management ─────────────────────────────────────────────


def create_access_token(
    subject: str,
    role: Role,
    scopes: Optional[list[Scope]] = None,
) -> str:
    """
    Create an RS256-signed JWT access token.

    Args:
        subject: User or service identifier
        role: RBAC role (admin, auditor, viewer)
        scopes: Optional override — defaults to role-based scopes

    Returns:
        RS256-signed JWT string
    """
    if scopes is None:
        scopes = ROLE_SCOPES.get(role, [Scope.audit_read])

    now = datetime.now(timezone.utc)
    payload = {
        "iss": "ai-governance-mcp-server",
        "sub": subject,
        "role": role.value,
        "scopes": [s.value for s in scopes],
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, _PRIVATE_KEY, algorithm=ALGORITHM)


def create_refresh_token(subject: str, role: Role) -> str:
    """Create a long-lived RS256-signed refresh token."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "ai-governance-mcp-server",
        "sub": subject,
        "role": role.value,
        "type": "refresh",
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, _PRIVATE_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate an RS256 JWT token.

    Raises:
        HTTPException(401) on invalid or expired tokens
    """
    try:
        payload = jwt.decode(token, _PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired. Request a new access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─── FastAPI Middleware ───────────────────────────────────────────


async def auth_middleware(request: Request, call_next: Callable):
    """
    FastAPI middleware that validates Bearer tokens on protected routes.

    Routes under /health and /api/auth are public.
    All other /api/* routes require authentication.

    Per-user RBAC: When the MCP server forwards user context via
    X-MCP-User-* headers, those are used for per-user scope enforcement.
    """
    path = request.url.path

    # Public routes
    if path == "/health" or path.startswith("/api/auth"):
        return await call_next(request)

    # Demo mode: bypass authentication (development only)
    if DEMO_MODE:
        request.state.user = "demo-auditor"
        request.state.role = "auditor"
        request.state.scopes = ["audit:read", "audit:write"]
        request.state.jti = "demo-" + uuid.uuid4().hex[:8]
        return await call_next(request)

    # Protected routes — require Bearer token
    if path.startswith("/api/"):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "missing_token",
                    "detail": "Authorization header with Bearer token required",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header.removeprefix("Bearer ")
        try:
            payload = decode_token(token)
            request.state.user = payload.get("sub", "unknown")
            request.state.role = payload.get("role", "viewer")
            request.state.scopes = payload.get("scopes", ["audit:read"])
            request.state.jti = payload.get("jti", "")
        except HTTPException:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "invalid_token", "detail": "Token validation failed"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Per-user RBAC: If MCP server forwards user context, use it
        mcp_user_id = request.headers.get("X-MCP-User-ID")
        mcp_user_role = request.headers.get("X-MCP-User-Role")
        mcp_user_scopes = request.headers.get("X-MCP-User-Scopes")
        if mcp_user_id:
            request.state.user = mcp_user_id
        if mcp_user_role:
            request.state.role = mcp_user_role
        if mcp_user_scopes:
            request.state.scopes = [s.strip() for s in mcp_user_scopes.split(",")]

    return await call_next(request)


# ─── Scope Check Decorator ───────────────────────────────────────


def require_scope(required_scope: Scope):
    """
    Decorator to enforce a specific scope on an endpoint.

    Usage:
        @router.post("/api/supply-chain/audit")
        @require_scope(Scope.audit_write)
        async def endpoint(...):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get("request") or kwargs.get("request_obj")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            if request is None:
                raise HTTPException(status_code=500, detail="Request object not found")

            user_scopes: list = getattr(request.state, "scopes", [])
            if required_scope.value not in user_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Insufficient scope. Required: '{required_scope.value}', "
                        f"have: {user_scopes}"
                    ),
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator
