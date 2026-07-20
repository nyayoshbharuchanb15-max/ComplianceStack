# SPDX-License-Identifier: Apache-2.0
"""Client-credentials JWT auth + scope enforcement + request-hash verification."""
from __future__ import annotations
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Request

from orchestrator.config import ROLE_SCOPES, jwt_secret, service_accounts, token_ttl_minutes
from store.hashing import canonical_json

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "governance-orchestrator"


def issue_token(client_id: str, client_secret: str) -> dict:
    account = service_accounts().get(client_id)
    # Use hmac.compare_digest for constant-time comparison, but only after
    # ensuring both sides are bytes/strings of comparable type — passing None
    # to compare_digest raises. Compare the account existence first with a
    # dummy value so the timing profile of "unknown client" and "bad secret"
    # is indistinguishable.
    expected_secret = account["secret"] if account else ""
    if not hmac.compare_digest(expected_secret, client_secret) or not account:
        raise HTTPException(status_code=401, detail={
            "code": "INVALID_CLIENT", "message": "Unknown client or bad secret"})
    role = account["role"]
    scopes = ROLE_SCOPES[role]
    now = datetime.now(timezone.utc)
    expires_in = token_ttl_minutes() * 60
    token = jwt.encode(
        {"sub": client_id, "role": role, "scopes": scopes, "type": "access",
         "iss": JWT_ISSUER, "iat": now,
         "exp": now + timedelta(seconds=expires_in)},
        jwt_secret(), algorithm=JWT_ALGORITHM)
    return {"accessToken": token, "tokenType": "Bearer", "expiresIn": expires_in,
            "role": role, "scopes": scopes}


def _decode_bearer(request: Request) -> dict:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={
            "code": "MISSING_TOKEN", "message": "Bearer token required"})
    try:
        # Pin the accepted algorithm (defence-in-depth vs alg-confusion) AND
        # require the `iss` claim so tokens minted by any co-located HS256
        # service can't be replayed against this orchestrator.
        return jwt.decode(header[7:], jwt_secret(),
                          algorithms=[JWT_ALGORITHM],
                          issuer=JWT_ISSUER,
                          options={"require": ["exp", "iat", "iss", "sub"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={
            "code": "TOKEN_EXPIRED", "message": "Token expired"})
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail={
            "code": "INVALID_TOKEN", "message": "Token issuer not recognised"})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail={
            "code": "INVALID_TOKEN", "message": "Token signature invalid"})


async def _verify_request_hash(request: Request) -> None:
    """When the TypeScript layer supplies X-Request-Hash, the body must match it."""
    supplied = request.headers.get("X-Request-Hash")
    if not supplied or request.method != "POST":
        return
    body = await request.body()
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail={
            "code": "MALFORMED_BODY", "message": "Body is not valid JSON"})
    expected = hashlib.sha256(canonical_json(parsed).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=400, detail={
            "code": "REQUEST_HASH_MISMATCH",
            "message": "Request body does not match X-Request-Hash"})


def require_scope(scope: str):
    async def dependency(request: Request) -> dict:
        claims = _decode_bearer(request)
        if scope not in claims.get("scopes", []):
            raise HTTPException(status_code=403, detail={
                "code": "INSUFFICIENT_SCOPE",
                "message": f"Scope '{scope}' required; role '{claims.get('role')}' lacks it"})
        await _verify_request_hash(request)
        return claims
    return dependency
