# SPDX-License-Identifier: Apache-2.0
"""E2E tests for the Emergent-managed Google Sign-In endpoints.

Uses the `GOOGLE_AUTH_TEST_SESSION_ID` fixture escape hatch so no egress to
`demobackend.emergentagent.com` is needed. Requires
`GOV_ALLOW_TEST_AUTH=1` in the backend env (already set in preview .env).
"""
from __future__ import annotations
import os
import httpx
import pytest

BASE = os.environ.get("GOVERNANCE_API_URL", "http://localhost:8001") + "/api/v1"

TEST_SESSION_ID = os.environ.get(
    "GOOGLE_AUTH_TEST_SESSION_ID", "test-fixture-session-id-abc123")
TEST_SESSION_TOKEN = os.environ.get(
    "GOOGLE_AUTH_TEST_SESSION_TOKEN", "test-fixture-session-token-xyz789")


class TestGoogleAuth:
    def test_exchange_requires_session_id_header(self):
        r = httpx.post(f"{BASE}/auth/google/session")
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "MISSING_SESSION_ID"

    def test_exchange_invalid_session_id_rejected(self):
        r = httpx.post(f"{BASE}/auth/google/session",
                       headers={"X-Session-ID": "definitely-not-real"})
        # Either Emergent responds 401 (real network) or backend maps 4xx→401.
        assert r.status_code in (401, 502)

    def test_exchange_with_fixture_returns_admin_jwt(self):
        r = httpx.post(f"{BASE}/auth/google/session",
                       headers={"X-Session-ID": TEST_SESSION_ID})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["role"] == "governance-admin"
        assert data["accessToken"]
        assert "certs:revoke" in data["scopes"]
        assert data["clientId"].startswith("google:")
        # Cookie must be set
        assert "governance_session" in r.headers.get("set-cookie", "")

    def test_me_endpoint_via_cookie(self):
        # httpx doesn't send Secure cookies over http:// — pass explicitly.
        r1 = httpx.post(f"{BASE}/auth/google/session",
                        headers={"X-Session-ID": TEST_SESSION_ID})
        r1.raise_for_status()
        r2 = httpx.get(f"{BASE}/auth/me",
                       cookies={"governance_session": TEST_SESSION_TOKEN})
        assert r2.status_code == 200
        data = r2.json()
        assert data["email"] == "test.user@governance.local"
        assert data["role"] == "governance-admin"
        assert isinstance(data["scopes"], list)

    def test_me_endpoint_via_bearer_session_token(self):
        # Refresh session to ensure token exists in DB
        httpx.post(f"{BASE}/auth/google/session",
                   headers={"X-Session-ID": TEST_SESSION_ID}).raise_for_status()
        r = httpx.get(f"{BASE}/auth/me",
                      headers={"Authorization": f"Bearer {TEST_SESSION_TOKEN}"})
        assert r.status_code == 200
        assert r.json()["email"] == "test.user@governance.local"

    def test_me_unauthenticated_returns_401(self):
        r = httpx.get(f"{BASE}/auth/me")
        assert r.status_code == 401
        assert r.json()["detail"]["code"] == "NOT_AUTHENTICATED"

    def test_google_jwt_grants_pipeline_access(self):
        r = httpx.post(f"{BASE}/auth/google/session",
                       headers={"X-Session-ID": TEST_SESSION_ID})
        r.raise_for_status()
        tok = r.json()["accessToken"]
        # Governance-admin should be able to list runs
        rr = httpx.get(f"{BASE}/runs?limit=1",
                       headers={"Authorization": f"Bearer {tok}"})
        assert rr.status_code == 200
        assert "runs" in rr.json()

    def test_logout_clears_session(self):
        # Establish a session, verify it works, then log out and verify the
        # DB row is gone (401 with the same session_token afterwards).
        httpx.post(f"{BASE}/auth/google/session",
                   headers={"X-Session-ID": TEST_SESSION_ID}).raise_for_status()
        cookies = {"governance_session": TEST_SESSION_TOKEN}
        assert httpx.get(f"{BASE}/auth/me", cookies=cookies).status_code == 200
        r = httpx.post(f"{BASE}/auth/logout", cookies=cookies)
        assert r.status_code == 204
        # DB session row removed → re-presenting the token fails.
        assert httpx.get(f"{BASE}/auth/me", cookies=cookies).status_code == 401
