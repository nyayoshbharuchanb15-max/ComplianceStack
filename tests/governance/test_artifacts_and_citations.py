# SPDX-License-Identifier: Apache-2.0
"""End-to-end test for evidence artifacts + article-level citations.

Verifies that:
  1. Intake accepts and persists evidenceArtifacts[].
  2. Every phase produces citedArtifacts + articleCitations + missingArtifacts.
  3. Missing artifacts are surfaced with the framework/article they would have
     evidenced.
  4. The /runs/{id}/artifacts endpoint returns both the artifacts and the
     per-phase citations.
"""
from __future__ import annotations
import os
from typing import Any

import httpx
import pytest

BASE = os.environ.get("GOVERNANCE_API_URL", "http://localhost:8001") + "/api/v1"


def _token(client: httpx.AsyncClient, cid: str, secret: str) -> str:
    r = httpx.post(f"{BASE}/auth/token",
                   json={"clientId": cid, "clientSecret": secret})
    r.raise_for_status()
    return r.json()["accessToken"]


@pytest.fixture
def admin_token() -> str:
    r = httpx.post(f"{BASE}/auth/token",
                   json={"clientId": "governance-admin",
                         "clientSecret": "govern-admin-secret-dev"})
    r.raise_for_status()
    return r.json()["accessToken"]


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _artifacts() -> list[dict[str, Any]]:
    """A comprehensive set covering every PHASE_EXPECTATIONS entry."""
    return [
        {"name": "Model Card v1", "type": "model_card", "uri": "internal://mc.md"},
        {"name": "ROPA", "type": "ropa_record", "uri": "internal://ropa.pdf"},
        {"name": "Risk Assessment", "type": "risk_assessment", "uri": "internal://ra.pdf"},
        {"name": "DPIA v1", "type": "dpia", "uri": "internal://dpia.pdf"},
        {"name": "Data Flow Map", "type": "data_flow_map", "uri": "internal://dfm.pdf"},
        {"name": "Consent Screenshots", "type": "consent_ux_evidence", "uri": "internal://ux.pdf"},
        {"name": "Bias Output", "type": "bias_test_output", "uri": "internal://bias.json"},
        {"name": "Fairness Report", "type": "fairness_metrics_report", "uri": "internal://fair.pdf"},
        {"name": "Dataset Lineage", "type": "dataset_lineage", "uri": "internal://lin.json"},
        {"name": "Adversarial Report", "type": "adversarial_test_report", "uri": "internal://adv.pdf"},
        {"name": "Robustness Log", "type": "robustness_test_log", "uri": "internal://rob.log"},
        {"name": "Security Audit", "type": "security_audit", "uri": "internal://sec.pdf"},
        {"name": "SHAP Report", "type": "explainability_report", "uri": "internal://shap.pdf"},
        {"name": "Decision Log Sample", "type": "decision_log_sample", "uri": "internal://dl.csv"},
        {"name": "Oversight Procedure", "type": "oversight_procedure", "uri": "internal://ovs.pdf"},
        {"name": "Killswitch Runbook", "type": "kill_switch_evidence", "uri": "internal://ks.md"},
        {"name": "Conformity Declaration", "type": "conformity_declaration", "uri": "internal://conf.pdf"},
        {"name": "Monitoring Dashboard", "type": "monitoring_dashboard", "uri": "internal://mon.png"},
    ]


def _fair_sample():
    return [{"attributes": {"gender": g}, "outcome": o, "label": o}
            for g in ("F", "M") for o in (1, 1, 0)]


def _run_full_pipeline(token: str, model_id: str,
                      arts: list[dict[str, Any]] | None = None) -> dict:
    intake = httpx.post(f"{BASE}/phases/intake", headers=_hdr(token), json={
        "modelId": model_id, "modelVersion": "1.0.0",
        "deploymentContext": {"sector": "employment", "regions": ["EU"], "autonomyLevel": "supervised"},
        "processingActivities": [{"name": "cv", "purpose": "rank"}],
        "datasets": [{"datasetId": "ds1", "containsPersonalData": True}],
        "evidenceArtifacts": arts if arts is not None else _artifacts(),
    })
    intake.raise_for_status()
    run_id = intake.json()["runId"]

    for phase, payload in [
        ("scope", {}),
        ("risk", {"riskInputs": {"annexIIICategories": ["employment"]}}),
        ("data-protection", {"dataProtection": {
            "processesPersonalData": True, "lawfulBasis": "legitimate_interest",
            "dpiaConducted": True, "dpoAppointed": True, "consentMechanism": True,
            "dataMinimisationApplied": True, "privacyByDesign": True,
            "retentionPeriodDays": 180, "crossBorderTransfers": []}}),
        ("fairness", {"sensitiveFeatures": ["gender"], "fairnessThreshold": 0.8,
                      "datasetSample": _fair_sample()}),
        ("robustness", {"testSuites": ["prompt_injection", "jailbreak"],
                        "securityControls": {
                            "inputSanitization": True, "outputFiltering": True,
                            "rateLimiting": True, "adversarialTraining": True,
                            "anomalyMonitoring": True, "accessControl": True}}),
        ("explainability", {"oversight": {"hasHumanInTheLoop": True, "hasKillSwitch": True,
                                            "overrideProcedureDocumented": True},
                             "explainability": {"method": "shap", "userFacingExplanations": True,
                                                "decisionLogsRetained": True, "logRetentionDays": 365}}),
        ("certification", {"issuer": {"name": "Test"}, "validityDays": 90}),
        ("monitoring", {"monitors": {"driftThreshold": 0.2, "fairnessDriftThreshold": 0.1}}),
    ]:
        body = {"runId": run_id, **payload}
        r = httpx.post(f"{BASE}/phases/{phase}", headers=_hdr(token), json=body)
        r.raise_for_status()
    return run_id


class TestArtifactsAndCitations:
    def test_intake_persists_artifacts(self, admin_token):
        arts = _artifacts()[:5]
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(admin_token), json={
            "modelId": f"art-test-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
            "evidenceArtifacts": arts,
        })
        r.raise_for_status()
        outputs = r.json()["outputs"]
        assert outputs["contextSummary"]["artifactCount"] == 5
        assert len(outputs["registeredArtifacts"]) == 5
        assert all(a["artifactId"].startswith("art_") for a in outputs["registeredArtifacts"])
        assert all(len(a["sha256"]) == 64 for a in outputs["registeredArtifacts"])

    def test_phase_outputs_carry_citations_and_missing(self, admin_token):
        run_id = _run_full_pipeline(admin_token, f"cite-test-{os.urandom(4).hex()}")

        run = httpx.get(f"{BASE}/runs/{run_id}", headers=_hdr(admin_token)).json()
        assert run["status"] == "monitoring_active"
        assert len(run["phases"]) == 9

        # Every phase result carries the new citation fields
        for ph in run["phases"]:
            outs = ph["outputs"]
            assert "citedArtifacts" in outs, f"{ph['phase']} missing citedArtifacts"
            assert "missingArtifacts" in outs, f"{ph['phase']} missing missingArtifacts"
            assert "articleCitations" in outs, f"{ph['phase']} missing articleCitations"

        # Fairness must have inspected bias_test_output against EU-AI-ACT Art. 10
        fair = next(p for p in run["phases"] if p["phase"] == "fairness")
        arts = fair["outputs"]["citedArtifacts"]
        assert any(a["type"] == "bias_test_output" and a["article"] == "Art. 10"
                   for a in arts), "fairness must cite bias_test_output against Art. 10"

    def test_missing_artifact_surfaced(self, admin_token):
        # Skip the DPIA — data_protection must record it as missing.
        arts = [a for a in _artifacts() if a["type"] != "dpia"]
        run_id = _run_full_pipeline(admin_token,
                                     f"miss-test-{os.urandom(4).hex()}", arts=arts)

        run = httpx.get(f"{BASE}/runs/{run_id}", headers=_hdr(admin_token)).json()
        dp = next(p for p in run["phases"] if p["phase"] == "data_protection")
        missing = dp["outputs"]["missingArtifacts"]
        assert any(m["expectedType"] == "dpia" and m["framework"] == "GDPR"
                   and m["article"] == "Art. 35" for m in missing)

    def test_artifacts_endpoint_returns_citations(self, admin_token):
        run_id = _run_full_pipeline(admin_token,
                                     f"art-end-{os.urandom(4).hex()}")
        r = httpx.get(f"{BASE}/runs/{run_id}/artifacts", headers=_hdr(admin_token))
        r.raise_for_status()
        data = r.json()
        assert len(data["artifacts"]) == 18
        # citations across phases → at least one per phase expectation
        phases = {c["phaseKey"] for c in data["citations"]}
        assert {"intake", "risk", "data_protection", "fairness",
                "robustness", "explainability", "certification",
                "monitoring"}.issubset(phases)

    def test_upload_additional_artifacts(self, admin_token):
        # Start a run, then append artifacts via the /runs/:id/artifacts endpoint.
        intake = httpx.post(f"{BASE}/phases/intake", headers=_hdr(admin_token), json={
            "modelId": f"upload-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
            "evidenceArtifacts": [],
        })
        intake.raise_for_status()
        run_id = intake.json()["runId"]

        r = httpx.post(f"{BASE}/runs/{run_id}/artifacts", headers=_hdr(admin_token), json={
            "artifacts": [{"name": "Late DPIA", "type": "dpia"}],
        })
        r.raise_for_status()
        assert r.json()["artifacts"][0]["type"] == "dpia"

        arts = httpx.get(f"{BASE}/runs/{run_id}/artifacts", headers=_hdr(admin_token)).json()
        assert any(a["type"] == "dpia" for a in arts["artifacts"])

    def test_runs_list_endpoint(self, admin_token):
        r = httpx.get(f"{BASE}/runs?limit=5", headers=_hdr(admin_token))
        r.raise_for_status()
        data = r.json()
        assert "runs" in data
        assert len(data["runs"]) <= 5
        if data["runs"]:
            r0 = data["runs"][0]
            assert {"runId", "modelId", "modelVersion", "status", "createdAt"} <= r0.keys()
