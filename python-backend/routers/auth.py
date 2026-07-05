# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Authentication Router — OAuth 2.1 Authorization Code Flow + PKCE
─────────────────────────────────────────────────────────────────
Production-grade authentication with PostgreSQL-backed user store,
RS256 JWTs, PKCE, state validation, and Redis session management.

OAuth 2.1 (RFC 6749, RFC 7636, draft-ietf-oauth-v2-1):
  - Authorization code flow with PKCE S256
  - State parameter for CSRF protection
  - Refresh token rotation
  - Token introspection (RFC 7662)
  - Token revocation with server-side blacklist

Endpoints:
  POST /api/auth/authorize   — Authorization endpoint (PKCE + state)
  POST /api/auth/token       — Token issuance (auth code + password grants)
  POST /api/auth/refresh     — Refresh token rotation
  GET  /api/auth/introspect  — Token introspection (RFC 7662)
  POST /api/auth/revoke      — Token revocation (Redis blacklist)
  GET  /api/auth/keys        — Public JWKS endpoint
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from db.user_store import user_store
from services.auth import (
    Role,
    Scope,
    ROLE_SCOPES,
    _PUBLIC_KEY,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_code_challenge,
    generate_code_verifier,
    generate_state,
)
from services.redis_webhook import webhook_engine

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# ─── Request / Response Models ───────────────────────────────────


class AuthorizeRequest(BaseModel):
    response_type: str = "code"
    client_id: str
    redirect_uri: str
    scope: str = "audit:read"
    state: str = ""
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    username: str
    password: str


class AuthorizeResponse(BaseModel):
    code: str
    state: str = ""


class TokenRequest(BaseModel):
    grant_type: str = "authorization_code"
    code: str = ""
    code_verifier: str = ""
    redirect_uri: str = ""
    username: str = ""
    password: str = ""
    scope: str = "audit:read"


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


class RefreshRequest(BaseModel):
    refresh_token: str


class IntrospectRequest(BaseModel):
    token: str


class IntrospectResponse(BaseModel):
    active: bool
    sub: str = ""
    role: str = ""
    scopes: list[str] = []
    exp: int = 0
    iat: int = 0
    jti: str = ""


class RevokeRequest(BaseModel):
    token: str


class PublicKeyResponse(BaseModel):
    algorithm: str = "RS256"
    key_type: str = "RSA"
    public_key_pem: str
    issuer: str = "ai-governance-mcp-server"


# ─── Redis Helpers ────────────────────────────────────────────────


async def _redis() -> Any:
    """Get the Redis client (lazy, may return None in tests)."""
    return getattr(webhook_engine, "client", None)


async def _blacklist_jti(jti: str, ttl_seconds: int) -> None:
    """Add a JWT's jti to the Redis blacklist with matching TTL."""
    r = await _redis()
    if r is not None:
        await r.setex(f"blacklist:{jti}", ttl_seconds, "revoked")


async def _is_jti_blacklisted(jti: str) -> bool:
    """Check if a JWT's jti has been revoked."""
    r = await _redis()
    if r is None:
        return False
    return bool(await r.exists(f"blacklist:{jti}"))


async def _store_session(sub: str, jti: str, ttl_seconds: int) -> None:
    """Store a refresh token session in Redis."""
    r = await _redis()
    if r is not None:
        await r.setex(
            f"session:{sub}:{jti}",
            ttl_seconds,
            json.dumps({"jti": jti, "sub": sub}),
        )


async def _delete_session(sub: str, jti: str) -> None:
    """Remove a refresh token session from Redis (rotation)."""
    r = await _redis()
    if r is not None:
        await r.delete(f"session:{sub}:{jti}")


# ─── Endpoints ────────────────────────────────────────────────────


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize(request: AuthorizeRequest):
    """
    OAuth 2.1 authorization endpoint with PKCE + state.

    Validates the resource owner credentials, generates a single-use
    authorization code bound to the PKCE code_challenge, and returns
    the code with the original state parameter.

    This replaces the password grant as the primary authentication flow.
    """
    user = await user_store.authenticate(request.username, request.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    code = generate_code_verifier()[:32]
    await user_store.store_auth_code(
        code=code,
        client_id=request.client_id,
        code_challenge=request.code_challenge,
        code_challenge_method=request.code_challenge_method or "S256",
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        auth_user=request.username,
    )

    return AuthorizeResponse(code=code, state=request.state)


@router.post("/token", response_model=TokenResponse)
async def token(request: TokenRequest):
    """
    OAuth 2.1 token endpoint.

    Supports two grant types:
      1. authorization_code — PKCE-verified code exchange
      2. password — legacy grant (maintained for migration)

    Issues an access token and refresh token with role-based scopes.
    Refresh token sessions are stored in Redis for rotation support.
    """
    user: Optional[dict[str, Any]] = None
    scope = request.scope

    if request.grant_type == "authorization_code":
        if not request.code or not request.code_verifier:
            raise HTTPException(status_code=400, detail="Missing code or code_verifier")

        code_record = await user_store.consume_auth_code(request.code)
        if code_record is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired, or already-used authorization code",
            )

        expected_challenge = generate_code_challenge(request.code_verifier)
        if expected_challenge != code_record["code_challenge"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="PKCE code_verifier does not match code_challenge",
            )

        username = code_record["auth_user"]
        user = await user_store.get_user(username)
        scope = code_record["scope"]

    elif request.grant_type == "password":
        if not request.username or not request.password:
            raise HTTPException(status_code=400, detail="Missing username or password")
        user = await user_store.authenticate(request.username, request.password)

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {request.grant_type}")

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    role = Role(user["role"])
    user_scopes = [s.strip() for s in scope.split(",") if s.strip()]
    allowed_scopes = user.get("scopes", [s.value for s in ROLE_SCOPES.get(role, [Scope.audit_read])])
    effective_scopes = [s for s in user_scopes if s in allowed_scopes]
    if not effective_scopes:
        effective_scopes = allowed_scopes[:1]

    scope_enum_list: list[Scope] = []
    for s in effective_scopes:
        try:
            scope_enum_list.append(Scope(s))
        except ValueError:
            continue

    access_token = create_access_token(
        subject=user["username"],
        role=role,
        scopes=scope_enum_list or None,
    )
    refresh_token = create_refresh_token(subject=user["username"], role=role)

    rt_payload = decode_token(refresh_token)
    await _store_session(
        sub=user["username"],
        jti=rt_payload.get("jti", ""),
        ttl_seconds=int(os.environ.get("AUTH_REFRESH_EXPIRE_DAYS", "7")) * 86400,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=3600,
        scope=",".join(effective_scopes),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest):
    """
    Refresh an expired access token using a valid refresh token.

    Implements refresh token rotation: the old refresh token is
    revoked and a new pair is issued. Redis sessions are rotated.
    """
    try:
        payload = decode_token(request.refresh_token)
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not a refresh token",
        )

    jti = payload.get("jti", "")
    if await _is_jti_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    subject = payload.get("sub", "unknown")
    role_name = payload.get("role", "viewer")
    role = Role(role_name)

    new_access = create_access_token(subject=subject, role=role)
    new_refresh = create_refresh_token(subject=subject, role=role)

    exp = payload.get("exp", 0)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    ttl = max(exp - now_ts, 3600)
    await _blacklist_jti(jti, ttl)
    await _delete_session(subject, jti)

    new_rt_payload = decode_token(new_refresh)
    await _store_session(
        sub=subject,
        jti=new_rt_payload.get("jti", ""),
        ttl_seconds=int(os.environ.get("AUTH_REFRESH_EXPIRE_DAYS", "7")) * 86400,
    )

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=3600,
        scope=",".join(s.value for s in ROLE_SCOPES.get(role, [Scope.audit_read])),
    )


@router.get("/introspect", response_model=IntrospectResponse)
async def introspect(request: Request, token: str = ""):
    """
    Token introspection (RFC 7662).

    Returns token metadata including active status, subject, role,
    scopes, and timestamps. Checks the Redis blacklist before
    returning active=True.
    """
    auth_header = request.headers.get("Authorization", "")
    if not token and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ")

    if not token:
        return IntrospectResponse(active=False)

    try:
        payload = decode_token(token)
    except HTTPException:
        return IntrospectResponse(active=False)

    jti = payload.get("jti", "")
    if await _is_jti_blacklisted(jti):
        return IntrospectResponse(active=False)

    return IntrospectResponse(
        active=True,
        sub=payload.get("sub", ""),
        role=payload.get("role", ""),
        scopes=payload.get("scopes", []),
        exp=payload.get("exp", 0),
        iat=payload.get("iat", 0),
        jti=jti,
    )


@router.post("/revoke")
async def revoke(request: RevokeRequest):
    """
    Revoke a token.

    Adds the token's jti to the Redis blacklist with a TTL matching
    the token's remaining expiry time. The /introspect endpoint and
    middleware will reject blacklisted tokens.
    """
    try:
        payload = decode_token(request.token)
        jti = payload.get("jti", "")
        exp = payload.get("exp", 0)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        ttl = max(exp - now_ts, 3600)
        await _blacklist_jti(jti, ttl)
        sub = payload.get("sub", "unknown")
        await _delete_session(sub, jti)
        return {"status": "revoked", "detail": "Token has been revoked", "jti": jti}
    except HTTPException:
        return {"status": "revoked", "detail": "Token recorded (already expired or invalid)"}


@router.get("/keys", response_model=PublicKeyResponse)
async def public_keys():
    """
    Public key endpoint for JWT verification.

    Returns the RSA public key in PEM format so that clients can
    verify RS256 JWT signatures without sharing the private key.
    In production, serve this over HTTPS with certificate pinning.
    """
    from cryptography.hazmat.primitives import serialization as crypto_serialization

    pem = _PUBLIC_KEY.public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return PublicKeyResponse(public_key_pem=pem)
