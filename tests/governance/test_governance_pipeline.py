# SPDX-License-Identifier: Apache-2.0
"""End-to-end test: sample model through all 9 phases → signed VC 2.0 certificate,
blocker gating, ordering enforcement, least privilege, reaudit, dead-letter routing.

Run against a live stack:  GOVERNANCE_API_URL=http://localhost:8001 pytest tests/governance -v
"""
from __future__ import annotations
import os
import time
import uuid

import httpx
import pytest

from tests.governance.conftest import CREDS

BASE = os.environ.get("GOVERNANCE_API_URL", "http://localhost:8001").rstrip("/")

COMPLIANT_DATASET = (
    [{"attributes": {"gender": "F"}, "outcome": 1, "label": 1} for _ in range(10)]
    + [{"attributes": {"gender": "F"}, "outcome": 0, "label": 0} for _ in range(10)]
    + [{"attributes": {"gender": "M"}, "outcome": 1, "label": 1} for _ in range(10)]
    + [{"attributes": {"gender": "M"}, "outcome": 0, "label": 0} for _ in range(10)]
)
BIASED_DATASET = (
    [{"attributes": {"gender": "F"}, "outcome": 0, "label": 1} for _ in range(18)]
    + [{"attributes": {"gender": "F"}, "outcome": 1, "label": 1} for _ in range(2)]
    + [{"attributes": {"gender": "M"}, "outcome": 1, "label": 1} for _ in range(18)]
    + [{"attributes": {"gender": "M"}, "outcome": 0, "label": 0} for _ in range(2)]
)
ALL_CONTROLS = {"inputSanitization": True, "outputFiltering": True, "rateLimiting": True,
                "adversarialTraining": True, "anomalyMonitoring": True, "accessControl": True}
SUITES = ["prompt_injection", "jailbreak", "data_extraction", "evasion", "poisoning_resilience"]


def get_token(client_id: str, secret: str) -> str:
    r = httpx.post(f"{BASE}/api/v1/auth/token",
                   json={"clientId": client_id, "clientSecret": secret}, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["accessToken"]


@pytest.fixture(scope="module")
def admin() -> httpx.Client:
    token = get_token("governance-admin", CREDS["governance-admin"])
    with httpx.Client(base_url=BASE, headers={"Authorization": f"Bearer {token}"},
                      timeout=60) as client:
        yield client


@pytest.fixture(scope="module")
def intake_officer() -> httpx.Client:
    token = get_token("intake-officer", CREDS["intake-officer"])
    with httpx.Client(base_url=BASE, headers={"Authorization": f"Bearer {token}"},
                      timeout=60) as client:
        yield client


def intake_payload(model_id: str) -> dict:
    return {
        "modelId": model_id,
        "modelVersion": "1.0.0",
        "ownerTeam": "ml-platform",
        "deploymentContext": {"sector": "employment", "regions": ["EU", "IN"],
                              "autonomyLevel": "supervised"},
        "processingActivities": [{
            "name": "candidate-screening", "purpose": "CV ranking for recruitment",
            "dataCategories": ["employment_history", "education"],
            "dataSubjects": ["job_applicants"], "crossBorder": True,
            "specialCategories": []}],
        "datasets": [{"datasetId": f"ds-{model_id}", "version": "1",
                      "containsPersonalData": True}],
    }


def run_happy_path(admin: httpx.Client, model_id: str) -> tuple[str, str]:
    """All 9 phases; returns (run_id, certificate_id)."""
    r = admin.post("/api/v1/phases/intake", json=intake_payload(model_id))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "passed"
    run_id = r.json()["runId"]

    r = admin.post("/api/v1/phases/scope", json={"runId": run_id})
    assert r.status_code == 200, r.text
    frameworks = r.json()["outputs"]["frameworks"]
    for fw in ("EU-AI-ACT", "GDPR", "DPDP-ACT", "NIST-AI-RMF", "ISO-42001"):
        assert fw in frameworks, frameworks

    r = admin.post("/api/v1/phases/risk", json={
        "runId": run_id,
        "riskInputs": {"annexIIICategories": ["employment"], "interactsWithHumans": True}})
    assert r.status_code == 200, r.text
    assert r.json()["outputs"]["riskTier"] == "high"

    r = admin.post("/api/v1/phases/data-protection", json={
        "runId": run_id,
        "dataProtection": {
            "processesPersonalData": True, "lawfulBasis": "legitimate_interests",
            "dpiaConducted": True, "dpoAppointed": True, "consentMechanism": True,
            "crossBorderTransfers": [{"destination": "IN", "mechanism": "scc"}],
            "retentionPeriodDays": 365, "dataMinimisationApplied": True,
            "privacyByDesign": True}})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "passed"

    r = admin.post("/api/v1/phases/fairness", json={
        "runId": run_id, "datasetSample": COMPLIANT_DATASET,
        "sensitiveFeatures": ["gender"], "fairnessThreshold": 0.8})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "passed"

    r = admin.post("/api/v1/phases/robustness", json={
        "runId": run_id, "testSuites": SUITES, "securityControls": ALL_CONTROLS})
    assert r.status_code == 200, r.text
    assert r.json()["outputs"]["overallResistance"] == 1.0

    r = admin.post("/api/v1/phases/explainability", json={
        "runId": run_id,
        "oversight": {"hasHumanInTheLoop": True, "hasKillSwitch": True,
                      "overrideProcedureDocumented": True, "oversightRoles": ["ml-ops"]},
        "explainability": {"method": "shap", "userFacingExplanations": True,
                           "decisionLogsRetained": True, "logRetentionDays": 365}})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "passed"

    r = admin.post("/api/v1/phases/certification", json={
        "runId": run_id, "issuer": {"name": "Acme Governance Board"}, "validityDays": 365})
    assert r.status_code == 200, r.text
    cert = r.json()["outputs"]
    credential = cert["credential"]
    assert "VerifiableCredential" in credential["type"]
    assert "AIComplianceAuditCredential" in credential["type"]
    assert credential["proof"]["type"] == "DataIntegrityProof"
    assert credential["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert credential["proof"]["proofPurpose"] == "assertionMethod"
    assert credential["proof"]["proofValue"].startswith("z")
    assert credential["issuer"]["id"].startswith("did:key:z")
    assert len(credential["credentialSubject"]["phaseResults"]) == 7

    r = admin.post("/api/v1/phases/monitoring", json={"runId": run_id, "monitors": {}})
    assert r.status_code == 200, r.text
    assert r.json()["outputs"]["armedTriggers"]

    return run_id, cert["certificateId"]


class TestFullPipeline:
    def test_nine_phases_and_certificate(self, admin):
        model_id = f"e2e-model-{uuid.uuid4().hex[:8]}"
        run_id, cert_id = run_happy_path(admin, model_id)

        run = admin.get(f"/api/v1/runs/{run_id}").json()
        assert run["status"] == "monitoring_active"
        assert len(run["phases"]) == 9
        # per-run hash chain: prev_hash links each record to its predecessor
        phases = run["phases"]
        for prev, cur in zip(phases, phases[1:]):
            assert cur["prevHash"] == prev["integrityHash"]
        assert run["certificateId"] == cert_id

        v = httpx.get(f"{BASE}/api/v1/certificates/{cert_id}/verify", timeout=30).json()
        assert v["verified"] is True
        assert v["checks"]["signatureValid"] is True
        assert v["checks"]["schemaValid"] is True
        assert v["checks"]["notRevoked"] is True

        lineage = admin.get(f"/api/v1/runs/{run_id}/lineage").json()
        labels = {label for n in lineage["nodes"] for label in n["labels"]}
        for expected in ("AuditRun", "Model", "PhaseResult", "TestExecution",
                         "EvidenceArtifact", "Control", "RegulatoryArticle",
                         "ProcessingActivity", "Dataset", "Certificate"):
            assert expected in labels, f"missing {expected} in {labels}"
        self.__class__.model_id = model_id
        self.__class__.cert_id = cert_id
        self.__class__.run_id = run_id

    def test_phase_ordering_enforced(self, admin):
        r = admin.post("/api/v1/phases/intake",
                       json=intake_payload(f"e2e-order-{uuid.uuid4().hex[:8]}"))
        run_id = r.json()["runId"]
        r = admin.post("/api/v1/phases/risk", json={"runId": run_id, "riskInputs": {}})
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "PRECONDITION_NOT_MET"
        r = admin.post("/api/v1/phases/scope", json={"runId": run_id})
        assert r.status_code == 200
        r = admin.post("/api/v1/phases/scope", json={"runId": run_id})
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "PHASE_ALREADY_EXECUTED"

    def test_blocker_halts_pipeline_and_blocks_cert(self, admin):
        r = admin.post("/api/v1/phases/intake",
                       json=intake_payload(f"e2e-blocked-{uuid.uuid4().hex[:8]}"))
        run_id = r.json()["runId"]
        admin.post("/api/v1/phases/scope", json={"runId": run_id})
        r = admin.post("/api/v1/phases/risk", json={
            "runId": run_id, "riskInputs": {"usesSocialScoring": True}})
        assert r.status_code == 200
        assert r.json()["status"] == "blocked"
        assert r.json()["blockers"][0]["code"] == "PROHIBITED_PRACTICE"
        r = admin.post("/api/v1/phases/fairness", json={
            "runId": run_id, "datasetSample": COMPLIANT_DATASET, "sensitiveFeatures": ["gender"]})
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "RUN_BLOCKED"
        r = admin.post("/api/v1/phases/certification", json={"runId": run_id})
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "CERTIFICATION_BLOCKED"

    def test_least_privilege_scopes(self, admin, intake_officer):
        r = admin.post("/api/v1/phases/intake",
                       json=intake_payload(f"e2e-rbac-{uuid.uuid4().hex[:8]}"))
        run_id = r.json()["runId"]
        r = intake_officer.post("/api/v1/phases/scope", json={"runId": run_id})
        assert r.status_code == 200  # in scope for intake-officer
        r = intake_officer.post("/api/v1/phases/risk", json={"runId": run_id, "riskInputs": {}})
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "INSUFFICIENT_SCOPE"
        r = httpx.post(f"{BASE}/api/v1/phases/risk",
                       json={"runId": run_id, "riskInputs": {}}, timeout=30)
        assert r.status_code == 401  # no token at all

    def test_request_hash_mismatch_rejected(self, admin):
        r = admin.post("/api/v1/phases/intake",
                       json=intake_payload(f"e2e-hash-{uuid.uuid4().hex[:8]}"),
                       headers={"X-Request-Hash": "0" * 64})
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "REQUEST_HASH_MISMATCH"


class TestReaudit:
    def test_reaudit_reissues_and_supersedes(self, admin):
        model_id = f"e2e-reissue-{uuid.uuid4().hex[:8]}"
        _, old_cert = run_happy_path(admin, model_id)
        r = admin.post("/api/v1/reaudit", json={
            "modelId": model_id,
            "trigger": {"type": "dataset_revision", "detail": "quarterly refresh",
                        "datasetId": f"ds-{model_id}"}})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["certificateAction"]["action"] == "reissued"
        assert body["certificateAction"]["previousCertificateId"] == old_cert
        assert set(body["impactScope"]["impactedPhases"]) == {"data_protection", "fairness"}
        assert "risk" in body["impactScope"]["carriedForwardPhases"]
        assert body["impactScope"]["affectedGraphNodes"], "impact resolver returned no nodes"
        assert body["findingsDiff"], "expected per-phase diff entries"

        old_status = httpx.get(f"{BASE}/api/v1/certificates/{old_cert}/status", timeout=30).json()
        assert old_status["status"] == "superseded"
        new_cert = body["certificateAction"]["newCertificateId"]
        v = httpx.get(f"{BASE}/api/v1/certificates/{new_cert}/verify", timeout=30).json()
        assert v["verified"] is True
        # new run carries reaudit lineage
        run = admin.get(f"/api/v1/runs/{body['reauditRunId']}").json()
        assert run["reauditOf"] == body["previousRunId"]
        carried = [p for p in run["phases"] if p["carriedForward"]]
        assert {p["phase"] for p in carried} == set(body["impactScope"]["carriedForwardPhases"])

    def test_reaudit_blocker_revokes_certificate(self, admin):
        model_id = f"e2e-revoke-{uuid.uuid4().hex[:8]}"
        _, cert_id = run_happy_path(admin, model_id)
        r = admin.post("/api/v1/reaudit", json={
            "modelId": model_id,
            "trigger": {"type": "dataset_revision", "detail": "revision introduced bias",
                        "datasetId": f"ds-{model_id}",
                        "updatedPhaseInputs": {
                            "fairness": {"datasetSample": BIASED_DATASET,
                                         "sensitiveFeatures": ["gender"],
                                         "fairnessThreshold": 0.8}}}})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["certificateAction"]["action"] == "revoked"
        assert body["runStatus"] == "blocked"
        diff = {d["phase"]: d for d in body["findingsDiff"]}
        assert "DISPARATE_IMPACT" in diff["fairness"]["blockersAdded"]
        v = httpx.get(f"{BASE}/api/v1/certificates/{cert_id}/verify", timeout=30).json()
        assert v["verified"] is False
        assert v["status"] == "revoked"

    def test_monitoring_observation_triggers_reaudit(self, admin):
        model_id = f"e2e-drift-{uuid.uuid4().hex[:8]}"
        run_happy_path(admin, model_id)
        r = admin.post("/api/v1/monitoring/observe", json={
            "modelId": model_id, "metrics": {"driftScore": 0.95}})
        assert r.status_code == 200, r.text
        assert r.json()["triggered"] is True
        assert r.json()["triggerType"] == "drift_threshold_breach"
        # the reaudit consumer executes asynchronously — poll the event ledger
        deadline = time.time() + 30
        executed = None
        while time.time() < deadline:
            events = admin.get("/api/v1/events/recent").json()["events"]
            executed = next((e for e in events if e["event_type"] == "reaudit.executed"
                             and e["payload"].get("modelId") == model_id), None)
            if executed:
                break
            time.sleep(2)
        assert executed, "reaudit consumer did not execute the drift-triggered reaudit"
        assert executed["payload"]["certificateAction"] == "reissued"


class TestEventFabric:
    def test_phase_events_delivered(self, admin):
        events = admin.get("/api/v1/events/recent").json()["events"]
        delivered = [e for e in events if e["status"] == "delivered"
                     and e["event_type"].startswith("phase.")]
        assert delivered, "no delivered phase events in the ledger"

    def test_poison_event_routed_to_dead_letter(self, admin):
        r = admin.post("/api/v1/events/test-dead-letter")
        assert r.status_code == 200
        event_id = r.json()["eventId"]
        deadline = time.time() + 45
        found = None
        while time.time() < deadline:
            dls = admin.get("/api/v1/events/dead-letter").json()["deadLetters"]
            found = next((d for d in dls if d.get("eventId") == event_id), None)
            if found:
                break
            time.sleep(2)
        assert found, "poison event never reached the dead-letter stream"
        assert int(found["attempts"]) >= 3
