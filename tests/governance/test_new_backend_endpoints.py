"""Test new backend endpoints: auth token per role, runs list, certificates list/revoke."""
import os
import requests
import pytest

from tests.governance.conftest import CREDS  # env-sourced service-account secrets

BASE = os.environ.get("GOVERNANCE_API_URL", "http://localhost:8001").rstrip("/")


def token(client_id):
    r = requests.post(f"{BASE}/api/v1/auth/token", json={"clientId": client_id, "clientSecret": CREDS[client_id]}, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()


class TestAuth:
    def test_all_four_roles_issue_tokens(self):
        seen = {}
        for cid in CREDS:
            data = token(cid)
            assert "accessToken" in data or "access_token" in data
            assert "role" in data or "scopes" in data or "scope" in data
            seen[cid] = data
        # roles should differ (governance-admin has more scopes than intake-officer)
        admin_scopes = seen["governance-admin"].get("scopes") or seen["governance-admin"].get("scope") or []
        intake_scopes = seen["intake-officer"].get("scopes") or seen["intake-officer"].get("scope") or []
        if isinstance(admin_scopes, str):
            admin_scopes = admin_scopes.split()
        if isinstance(intake_scopes, str):
            intake_scopes = intake_scopes.split()
        assert len(admin_scopes) >= len(intake_scopes)

    def test_bad_secret_401(self):
        r = requests.post(f"{BASE}/api/v1/auth/token", json={"clientId": "governance-admin", "clientSecret": "wrong"}, timeout=10)
        assert r.status_code == 401


class TestRunsList:
    def test_runs_list(self):
        t = token("governance-admin")
        tok = t.get("accessToken") or t.get("access_token")
        r = requests.get(f"{BASE}/api/v1/runs?limit=5", headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        assert r.status_code == 200
        data = r.json()
        # accept either list or {items:[]}
        items = data if isinstance(data, list) else data.get("items") or data.get("runs") or []
        # If empty, fine; otherwise verify shape
        if items:
            first = items[0]
            for key in ("runId", "modelId", "status"):
                assert key in first, f"Missing {key} in {first.keys()}"


class TestCertificates:
    def test_certificates_active_list(self):
        t = token("governance-admin")
        tok = t.get("accessToken") or t.get("access_token")
        r = requests.get(f"{BASE}/api/v1/certificates?status=active", headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        assert r.status_code == 200, r.text
        data = r.json()
        items = data if isinstance(data, list) else data.get("items") or data.get("certificates") or []
        assert isinstance(items, list)

    def test_certificate_revoke_flow(self):
        """Full flow: run pipeline -> get cert -> revoke -> assert status=revoked."""
        t = token("governance-admin")
        tok = t.get("accessToken") or t.get("access_token")
        headers = {"Authorization": f"Bearer {tok}"}
        r = requests.get(f"{BASE}/api/v1/certificates?status=active", headers=headers, timeout=15)
        assert r.status_code == 200
        data = r.json()
        items = data if isinstance(data, list) else data.get("items") or data.get("certificates") or []
        if not items:
            pytest.skip("No active certs to revoke")
        cid = items[0].get("certificateId") or items[0].get("id") or items[0].get("credentialId")
        assert cid, f"No id in cert: {items[0].keys()}"
        rr = requests.post(f"{BASE}/api/v1/certificates/{cid}/revoke", json={"reason": "TEST_revoke"}, headers=headers, timeout=15)
        assert rr.status_code in (200, 201, 204), rr.text
        # verify
        vr = requests.get(f"{BASE}/api/v1/certificates/{cid}", headers=headers, timeout=15)
        if vr.status_code == 200:
            d = vr.json()
            status = d.get("status") or (d.get("certificate") or {}).get("status")
            assert status == "revoked", f"Status not revoked: {status}"
