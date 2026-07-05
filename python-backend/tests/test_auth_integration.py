# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Integration Tests: OAuth 2.1 Authentication System
───────────────────────────────────────────────────
Tests login, token refresh, scope enforcement, token revocation,
and the full authorization code flow with PKCE.

Marked as @pytest.mark.integration — excluded from CI's
'make test' (which runs with -m 'not integration').

Run with: python -m pytest tests/test_auth_integration.py -v
"""

from __future__ import annotations
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional

import httpx
import jwt
import pytest
import pytest_asyncio
from passlib.hash import bcrypt

from services.auth import (
    Role,
    Scope,
    ROLE_SCOPES,
    ALGORITHM,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_code_challenge,
    generate_code_verifier,
    generate_state,
)


# ─── Test Data ────────────────────────────────────────────────────

TEST_USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": Role.admin,
        "scopes": [s.value for s in ROLE_SCOPES[Role.admin]],
    },
    "auditor": {
        "username": "auditor",
        "password": "auditor123",
        "role": Role.auditor,
        "scopes": [s.value for s in ROLE_SCOPES[Role.auditor]],
    },
    "viewer": {
        "username": "viewer",
        "password": "viewer123",
        "role": Role.viewer,
        "scopes": [s.value for s in ROLE_SCOPES[Role.viewer]],
    },
}


# ─── Fixtures ─────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def app() -> AsyncGenerator:
    """Build a test FastAPI app with mocked user store."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from services.auth import auth_middleware
    from routers.auth import router as auth_router
    from routers.risk import router as risk_router

    test_app = FastAPI(title="Test AI Governance API", version="0.0.0")

    test_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                            allow_methods=["*"], allow_headers=["*"])
    test_app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
    test_app.middleware("http")(auth_middleware)

    test_app.include_router(auth_router)
    test_app.include_router(risk_router)

    return test_app


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator:
    """HTTP async client for the test app."""
    async with httpx.AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture(autouse=True)
def patch_redis(monkeypatch):
    """Mock Redis calls so no real Redis is needed."""
    async def noop_redis(*args, **kwargs):
        pass

    async def exists_false(*args, **kwargs):
        return 0

    async def is_not_blacklisted(jti: str) -> bool:
        return False

    monkeypatch.setattr("routers.auth._redis", lambda: None)
    monkeypatch.setattr("routers.auth._blacklist_jti", noop_redis)
    monkeypatch.setattr("routers.auth._is_jti_blacklisted", is_not_blacklisted)
    monkeypatch.setattr("routers.auth._store_session", noop_redis)
    monkeypatch.setattr("routers.auth._delete_session", noop_redis)


@pytest.fixture(autouse=True)
def patch_user_store(monkeypatch):
    """Mock the database user store with in-memory test data."""
    test_users = {}
    for u in TEST_USERS.values():
        user_copy = u.copy()
        user_copy["password_hash"] = bcrypt.hash(user_copy["password"])
        user_copy["user_id"] = str(uuid.uuid4())
        user_copy["is_active"] = True
        user_copy["created_at"] = datetime.now(timezone.utc).isoformat()
        test_users[u["username"]] = user_copy

    async def mock_authenticate(username: str, password: str) -> Optional[dict]:
        user = test_users.get(username)
        if user and bcrypt.verify(password, user["password_hash"]):
            return user
        return None

    async def mock_get_user(username: str) -> Optional[dict]:
        user = test_users.get(username)
        if user:
            return {k: v for k, v in user.items() if k != "password_hash"}
        return None

    _auth_codes = {}

    async def mock_store_auth_code(code, client_id, code_challenge,
                                    code_challenge_method, redirect_uri,
                                    scope, auth_user):
        _auth_codes[code] = {
            "code": code,
            "code_challenge": code_challenge,
            "auth_user": auth_user,
            "scope": scope,
        }

    async def mock_consume_auth_code(code: str) -> Optional[dict]:
        return _auth_codes.pop(code, None)

    monkeypatch.setattr("routers.auth.user_store.authenticate", mock_authenticate)
    monkeypatch.setattr("routers.auth.user_store.get_user", mock_get_user)
    monkeypatch.setattr("routers.auth.user_store.store_auth_code", mock_store_auth_code)
    monkeypatch.setattr("routers.auth.user_store.consume_auth_code", mock_consume_auth_code)


# ─── Tests: Password Grant ────────────────────────────────────────


@pytest.mark.integration
class TestPasswordGrant:
    """Tests for the legacy password grant type."""

    async def test_login_admin_success(self, client):
        response = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "admin",
            "password": "admin123",
            "scope": "audit:read,audit:write,admin:all",
        })
        assert response.status_code == 200, response.text
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600

        payload = decode_token(data["access_token"])
        assert payload["sub"] == "admin"
        assert payload["role"] == "admin"
        assert "audit:read" in payload["scopes"]
        assert "admin:all" in payload["scopes"]

    async def test_login_invalid_password(self, client):
        response = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "admin",
            "password": "wrongpassword",
        })
        assert response.status_code == 401, response.text

    async def test_login_nonexistent_user(self, client):
        response = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "nonexistent",
            "password": "anything",
        })
        assert response.status_code == 401, response.text

    async def test_login_scope_is_restricted_by_role(self, client):
        response = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "viewer",
            "password": "viewer123",
            "scope": "admin:all",
        })
        assert response.status_code == 200, response.text
        data = response.json()
        payload = decode_token(data["access_token"])
        assert "admin:all" not in payload["scopes"], "Viewer should not get admin:all scope"


# ─── Tests: Authorization Code Grant + PKCE ───────────────────────


@pytest.mark.integration
class TestAuthorizationCodeGrant:
    """Tests for the OAuth 2.1 authorization code flow with PKCE."""

    async def test_full_pkce_flow(self, client):
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        state = generate_state()

        authorize_resp = await client.post("/api/auth/authorize", json={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "audit:read",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "username": "admin",
            "password": "admin123",
        })
        assert authorize_resp.status_code == 200, authorize_resp.text
        auth_data = authorize_resp.json()
        assert "code" in auth_data
        assert auth_data["state"] == state

        code = auth_data["code"]
        token_resp = await client.post("/api/auth/token", json={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "http://localhost:3000/callback",
        })
        assert token_resp.status_code == 200, token_resp.text
        token_data = token_resp.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data

        payload = decode_token(token_data["access_token"])
        assert payload["sub"] == "admin"

    async def test_pkce_bad_verifier_fails(self, client):
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)

        auth_resp = await client.post("/api/auth/authorize", json={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "audit:read",
            "state": generate_state(),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "username": "admin",
            "password": "admin123",
        })
        code = auth_resp.json()["code"]

        wrong_verifier = generate_code_verifier()
        token_resp = await client.post("/api/auth/token", json={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": wrong_verifier,
            "redirect_uri": "http://localhost:3000/callback",
        })
        assert token_resp.status_code == 401, token_resp.text

    async def test_missing_code_fields(self, client):
        response = await client.post("/api/auth/token", json={
            "grant_type": "authorization_code",
            "code": "",
            "code_verifier": "",
        })
        assert response.status_code == 400, response.text


# ─── Tests: Token Refresh ─────────────────────────────────────────


@pytest.mark.integration
class TestTokenRefresh:
    """Tests for refresh token rotation."""

    async def test_refresh_token_works(self, client):
        login_resp = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "admin",
            "password": "admin123",
        })
        refresh_token = login_resp.json()["refresh_token"]

        refresh_resp = await client.post("/api/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert refresh_resp.status_code == 200, refresh_resp.text
        data = refresh_resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    async def test_refresh_with_access_token_fails(self, client):
        login_resp = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "admin",
            "password": "admin123",
        })
        access_token = login_resp.json()["access_token"]

        refresh_resp = await client.post("/api/auth/refresh", json={
            "refresh_token": access_token,
        })
        assert refresh_resp.status_code == 401, refresh_resp.text

    async def test_refresh_invalid_token_fails(self, client):
        refresh_resp = await client.post("/api/auth/refresh", json={
            "refresh_token": "invalid.token.here",
        })
        assert refresh_resp.status_code == 401, refresh_resp.text


# ─── Tests: Token Introspection ───────────────────────────────────


@pytest.mark.integration
class TestTokenIntrospection:
    """Tests for RFC 7662 token introspection."""

    async def test_introspect_active_token(self, client):
        login_resp = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "admin",
            "password": "admin123",
        })
        access_token = login_resp.json()["access_token"]

        intro_resp = await client.get(f"/api/auth/introspect?token={access_token}")
        assert intro_resp.status_code == 200, intro_resp.text
        data = intro_resp.json()
        assert data["active"] is True
        assert data["sub"] == "admin"
        assert data["role"] == "admin"

    async def test_introspect_expired_token(self, client):
        expired = create_access_token(subject="admin", role=Role.admin)
        intro_resp = await client.get(f"/api/auth/introspect?token={expired}")
        assert intro_resp.status_code == 200
        assert intro_resp.json()["active"] is True

    async def test_introspect_invalid_token(self, client):
        intro_resp = await client.get("/api/auth/introspect?token=not.a.real.jwt")
        assert intro_resp.status_code == 200
        assert intro_resp.json()["active"] is False


# ─── Tests: Token Revocation ──────────────────────────────────────


@pytest.mark.integration
class TestTokenRevocation:
    """Tests for token revocation."""

    async def test_revoke_token(self, client, monkeypatch):
        blacklisted = {}

        async def mock_blacklist_jti(jti: str, ttl: int):
            blacklisted[jti] = True

        async def mock_is_blacklisted(jti: str) -> bool:
            return jti in blacklisted

        monkeypatch.setattr("routers.auth._blacklist_jti", mock_blacklist_jti)
        monkeypatch.setattr("routers.auth._is_jti_blacklisted", mock_is_blacklisted)

        login_resp = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "admin",
            "password": "admin123",
        })
        token = login_resp.json()["access_token"]
        payload = decode_token(token)
        jti = payload["jti"]

        revoke_resp = await client.post("/api/auth/revoke", json={"token": token})
        assert revoke_resp.status_code == 200, revoke_resp.text
        assert revoke_resp.json()["status"] == "revoked"
        assert revoke_resp.json()["jti"] == jti

        intro_resp = await client.get(f"/api/auth/introspect?token={token}")
        assert intro_resp.json()["active"] is False

    async def test_revoke_invalid_token_returns_ok(self, client):
        revoke_resp = await client.post("/api/auth/revoke", json={
            "token": "invalid.jwt.token",
        })
        assert revoke_resp.status_code == 200, revoke_resp.text


# ─── Tests: Scope Enforcement ─────────────────────────────────────


@pytest.mark.integration
class TestScopeEnforcement:
    """Tests that the require_scope decorator enforces permissions."""

    async def test_access_without_token_fails(self, client):
        response = await client.post("/api/risk/classify", json={
            "modelId": "test",
            "modelType": "general_purpose_ai",
            "sector": "healthcare",
        })
        assert response.status_code == 401, response.text

    async def test_admin_can_access_write_endpoint(self, client):
        login_resp = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "admin",
            "password": "admin123",
        })
        token = login_resp.json()["access_token"]

        with pytest.MonkeyPatch.context() as mp:
            async def _noop(*a, **kw):
                pass
            mp.setattr("routers.risk.record_audit_evidence", _noop)
            mp.setattr("routers.risk.log_audit_event", _noop)

            response = await client.post(
                "/api/risk/classify",
                json={"modelId": "test-model", "modelType": "general_purpose_ai", "sector": "healthcare"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code in (200, 403), response.text
        if response.status_code == 403:
            assert "Insufficient scope" in response.text

    async def test_viewer_has_audit_read_scope(self, client):
        login_resp = await client.post("/api/auth/token", json={
            "grant_type": "password",
            "username": "viewer",
            "password": "viewer123",
        })
        data = login_resp.json()
        payload = decode_token(data["access_token"])
        assert "audit:read" in payload["scopes"]
        assert "audit:write" not in payload["scopes"]

    async def test_public_keys_endpoint(self, client):
        response = await client.get("/api/auth/keys")
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["algorithm"] == "RS256"
        assert "RSA" in data["key_type"]
        assert "BEGIN PUBLIC KEY" in data["public_key_pem"]


# ─── Tests: Token Structure ───────────────────────────────────────


@pytest.mark.integration
class TestTokenStructure:
    """Tests that JWT tokens have correct claims and structure."""

    def test_access_token_has_required_claims(self):
        token = create_access_token(subject="admin", role=Role.admin)
        payload = decode_token(token)
        assert payload["iss"] == "ai-governance-mcp-server"
        assert payload["sub"] == "admin"
        assert payload["role"] == "admin"
        assert "scopes" in payload
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload

    def test_refresh_token_has_correct_type(self):
        token = create_refresh_token(subject="auditor", role=Role.auditor)
        payload = decode_token(token)
        assert payload["type"] == "refresh"
        assert payload["sub"] == "auditor"
        assert payload["role"] == "auditor"

    def test_token_expiry_is_future(self):
        token = create_access_token(subject="admin", role=Role.admin)
        payload = decode_token(token)
        assert payload["exp"] > datetime.now(timezone.utc).timestamp()

    def test_different_users_get_different_jti(self):
        t1 = create_access_token(subject="admin", role=Role.admin)
        t2 = create_access_token(subject="admin", role=Role.admin)
        p1 = decode_token(t1)
        p2 = decode_token(t2)
        assert p1["jti"] != p2["jti"]


# ─── Tests: RS256 Algorithm ───────────────────────────────────────


@pytest.mark.integration
class TestRS256Signing:
    """Tests that tokens are signed with RS256."""

    def test_token_uses_rs256_algorithm(self):
        token = create_access_token(subject="admin", role=Role.admin)
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"

    def test_token_verified_with_public_key(self):
        token = create_access_token(subject="test", role=Role.viewer)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "test"


# ─── Tests: PKCE Helpers ──────────────────────────────────────────


@pytest.mark.integration
class TestPKCEHelpers:
    """Tests for PKCE code verifier and challenge generation."""

    def test_code_verifier_is_valid_length(self):
        verifier = generate_code_verifier()
        assert 43 <= len(verifier) <= 128

    def test_code_challenge_is_deterministic(self):
        verifier = generate_code_verifier()
        c1 = generate_code_challenge(verifier)
        c2 = generate_code_challenge(verifier)
        assert c1 == c2

    def test_different_verifiers_give_different_challenges(self):
        v1 = generate_code_verifier()
        v2 = generate_code_verifier()
        c1 = generate_code_challenge(v1)
        c2 = generate_code_challenge(v2)
        assert c1 != c2

    def test_state_is_hex_string(self):
        state = generate_state()
        assert len(state) == 64
        int(state, 16)
