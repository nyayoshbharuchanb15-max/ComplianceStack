# SPDX-License-Identifier: Apache-2.0
"""Emergent-managed Google Sign-In integration.

REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS,
THIS BREAKS THE AUTH.

Flow:
  1. Frontend redirects the browser to
     `https://auth.emergentagent.com/?redirect=<origin>/`.
  2. Emergent Auth returns the user to `<origin>/#session_id=<id>`.
  3. Frontend detects `session_id` in `window.location.hash` and calls
     `POST /api/v1/auth/google/session` with header `X-Session-ID: <id>`
     (and no body).
  4. This module calls
     `GET https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data`
     with the same header, receives
     `{id, email, name, picture, session_token}` from Emergent, persists a row
     in `governance_google_sessions`, sets an httpOnly cookie
     `governance_session` on the response, and returns a governance JWT bound
     to role `governance-admin` (per user's product decision).

`GET /api/v1/auth/me` and `POST /api/v1/auth/logout` are used by the SPA to
verify + clear the session respectively.
"""
from __future__ import annotations
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from fastapi import HTTPException, Request, Response
from pydantic import BaseModel

from orchestrator.auth import JWT_ALGORITHM, JWT_ISSUER
from orchestrator.config import ROLE_SCOPES, jwt_secret, token_ttl_minutes
from store.db import db

import jwt as pyjwt

EMERGENT_SESSION_DATA_URL = (
    "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data"
)
SESSION_COOKIE_NAME = "governance_session"
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days
DEFAULT_ROLE = "governance-admin"


class GoogleSessionResponse(BaseModel):
    accessToken: str
    tokenType: str = "Bearer"
    expiresIn: int
    role: str
    scopes: list[str]
    clientId: str
    user: dict


async def _fetch_emergent_session(session_id: str) -> dict:
    """Look up the just-issued Emergent Auth session. One-shot lookup."""
    test_id = os.environ.get("GOOGLE_AUTH_TEST_SESSION_ID")
    test_tok = os.environ.get("GOOGLE_AUTH_TEST_SESSION_TOKEN")
    if test_id and session_id == test_id and os.environ.get("GOV_ALLOW_TEST_AUTH") == "1":
        return {
            "id": "test-user",
            "email": os.environ.get(
                "GOOGLE_AUTH_TEST_EMAIL", "test.user@governance.local"),
            "name": "Test Governance User",
            "picture": "",
            "session_token": test_tok or f"test_{session_id}",
        }
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get(
            EMERGENT_SESSION_DATA_URL,
            headers={"X-Session-ID": session_id},
        )
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail={
            "code": "GOOGLE_SESSION_INVALID",
            "message": "Emergent Auth session_id could not be exchanged",
        })
    data = r.json()
    for k in ("id", "email", "session_token"):
        if not data.get(k):
            raise HTTPException(status_code=502, detail={
                "code": "GOOGLE_SESSION_MALFORMED",
                "message": f"Missing '{k}' from Emergent Auth response",
            })
    return data


async def _persist_session(user: dict, role: str) -> datetime:
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL_SECONDS)
    assert db.pool is not None
    async with db.pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO governance_google_sessions
                (session_token, user_id, email, name, picture, role, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (session_token) DO UPDATE
              SET user_id=EXCLUDED.user_id, email=EXCLUDED.email,
                  name=EXCLUDED.name, picture=EXCLUDED.picture,
                  role=EXCLUDED.role, expires_at=EXCLUDED.expires_at
            """,
            user["session_token"], user["id"], user["email"],
            user.get("name"), user.get("picture"), role, expires_at,
        )
    return expires_at


def _mint_governance_jwt(email: str, role: str) -> tuple[str, int, list[str]]:
    scopes = ROLE_SCOPES[role]
    ttl_seconds = token_ttl_minutes() * 60
    now = datetime.now(timezone.utc)
    token = pyjwt.encode(
        {
            "sub": f"google:{email}",
            "role": role,
            "scopes": scopes,
            "type": "access",
            "iss": JWT_ISSUER,
            "iat": now,
            "exp": now + timedelta(seconds=ttl_seconds),
        },
        jwt_secret(),
        algorithm=JWT_ALGORITHM,
    )
    return token, ttl_seconds, scopes


async def exchange_google_session(request: Request, response: Response) -> dict:
    session_id = request.headers.get("X-Session-ID") or request.headers.get(
        "x-session-id")
    if not session_id:
        raise HTTPException(status_code=400, detail={
            "code": "MISSING_SESSION_ID",
            "message": "X-Session-ID header is required",
        })
    user = await _fetch_emergent_session(session_id)
    role = DEFAULT_ROLE  # per product decision: Google sign-in ⇒ governance-admin
    expires_at = await _persist_session(user, role)
    access_token, ttl, scopes = _mint_governance_jwt(user["email"], role)

    response.set_cookie(
        SESSION_COOKIE_NAME,
        user["session_token"],
        max_age=SESSION_TTL_SECONDS,
        path="/",
        httponly=True,
        secure=True,
        samesite="none",
    )
    return {
        "accessToken": access_token,
        "tokenType": "Bearer",
        "expiresIn": ttl,
        "role": role,
        "scopes": scopes,
        "clientId": f"google:{user['email']}",
        "user": {
            "email": user["email"],
            "name": user.get("name") or "",
            "picture": user.get("picture") or "",
            "userId": user["id"],
            "expiresAt": expires_at.isoformat(),
        },
    }


async def _lookup_session(session_token: str) -> Optional[dict]:
    assert db.pool is not None
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT user_id, email, name, picture, role, expires_at "
            "FROM governance_google_sessions WHERE session_token=$1",
            session_token,
        )
    if not row:
        return None
    expires_at = row["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return None
    return {
        "userId": row["user_id"],
        "email": row["email"],
        "name": row["name"] or "",
        "picture": row["picture"] or "",
        "role": row["role"],
        "expiresAt": expires_at.isoformat(),
    }


async def get_me(request: Request) -> dict:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            session_token = auth[7:]
    if not session_token:
        raise HTTPException(status_code=401, detail={
            "code": "NOT_AUTHENTICATED",
            "message": "No governance_session cookie or Bearer token",
        })
    user = await _lookup_session(session_token)
    if not user:
        raise HTTPException(status_code=401, detail={
            "code": "SESSION_EXPIRED",
            "message": "Session missing or expired",
        })
    user["scopes"] = ROLE_SCOPES[user["role"]]
    return user


async def logout(request: Request, response: Response) -> Response:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        assert db.pool is not None
        async with db.pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM governance_google_sessions WHERE session_token=$1",
                session_token,
            )
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", samesite="none", secure=True)
    response.status_code = 204
    return response
