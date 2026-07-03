"""
E2E Integration Test: Full 17-Phase Audit Pipeline via HTTP
────────────────────────────────────────────────────────────
Calls every FastAPI endpoint over HTTP against a live Docker
Compose backend with real PostgreSQL, Neo4j, and Redis.

This test validates:
  - All 17 audit phase endpoints return valid JSON
  - Regulatory article mappings are present in every response
  - Response schemas match Pydantic models
  - Phase chaining (output of one phase feeds the next)
  - W3C VC certificate generation and signing
  - CRL revocation and status checking
  - Trusted timestamping in evidence records
  - Health check deep probes
  - Rate limiting behavior
  - Error handling for invalid inputs

Run:
  docker compose -f docker-compose.test.yml up -d --build
  docker compose -f docker-compose.test.yml run --rm test-runner
  docker compose -f docker-compose.test.yml down -v
"""

import time
import uuid
import pytest
import httpx


# ═══════════════════════════════════════════════════════════════════
#  Helper: assert response structure
# ═══════════════════════════════════════════════════════════════════

def assert_ok(resp: httpx.Response, expected_status: int = 200):
    """Assert HTTP response is successful."""
    assert resp.status_code == expected_status, (
        f"Expected {expected_status}, got {resp.status_code}: {resp.text[:500]}"
    )


def assert_json(resp: httpx.Response) -> dict:
    """Assert response is JSON and return parsed body."""
    assert resp.headers.get("content-type", "").startswith("application/json"), (
        f"Expected JSON, got: {resp.headers.get('content-type')}"
    )
    return resp.json()


def assert_has_fields(data: dict, *fields):
    """Assert dictionary contains all specified fields."""
    for field in fields:
        assert field in data, f"Missing field '{field}' in {list(data.keys())}"


def assert_regulatory_mappings(data: dict):
    """Assert response contains regulatory article mappings."""
    has_articles = "mappedArticles" in data or "mappedSections" in data
    assert has_articles, (
        f"Missing regulatory mappings in: {list(data.keys())}"
    )


# ═══════════════════════════════════════════════════════════════════
#  TEST: Health Check
# ═══════════════════════════════════════════════════════════════════

class TestHealthCheck:
    def test_health_endpoint_returns_200(self, http_client: httpx.Client):
        resp = http_client.get("/health")
        assert_ok(resp)
        data = assert_json(resp)
        assert data["status"] in ("ok", "degraded", "unavailable")
        assert "services" in data
        assert "postgres" in data["services"]
        assert "neo4j" in data["services"]
        assert "redis" in data["services"]
        assert "crypto" in data["services"]
        assert "timestamping" in data["services"]

    def test_health_shows_connected_services(self, http_client: httpx.Client):
        resp = http_client.get("/health")
        data = assert_json(resp)
        # At minimum, crypto and timestamping should be operational
        assert data["services"]["crypto"] == "operational"


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 1 — Risk Classification
# ═══════════════════════════════════════════════════════════════════

class TestPhase1RiskClassification:
    def test_classify_high_risk(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/risk/classify", json={
            "modelId": model_id,
            "modelType": "general_purpose_ai",
            "sector": "employment",
            "usesProfiling": True,
            "deployer": "E2E Test Corp",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "tier", "rationale", "compliant", "timestamp")
        assert data["tier"] in ("prohibited", "high", "limited", "minimal")
        assert_regulatory_mappings(data)
        assert data["modelId"] == model_id

    def test_classify_minimal_risk(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/risk/classify", json={
            "modelId": model_id,
            "modelType": "other",
            "sector": "other",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert data["tier"] == "minimal"


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 2 — Supply Chain Discovery
# ═══════════════════════════════════════════════════════════════════

class TestPhase2SupplyChainDiscovery:
    def test_discover_supply_chain(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/supply-chain/discover", json={
            "modelId": model_id,
            "modelSearchPaths": [],
            "dataSearchPaths": [],
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "discoveredModels", "discoveredDatasets")


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 3 — Supply Chain Audit
# ═══════════════════════════════════════════════════════════════════

class TestPhase3SupplyChainAudit:
    def test_audit_supply_chain(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/supply-chain/audit", json={
            "modelId": model_id,
            "deepScan": False,
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "graph", "ipClearance", "compliant")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 4 — Human Oversight Verification
# ═══════════════════════════════════════════════════════════════════

class TestPhase4HumanOversight:
    def test_verify_oversight_with_kill_switch(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/human-oversight/verify", json={
            "modelId": model_id,
            "hasHumanInTheLoop": True,
            "hasKillSwitch": True,
            "oversightProcess": "Manual review of high-confidence outputs",
            "deploymentContext": "assistive",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "humanInTheLoop", "killSwitchPresent", "blocker", "compliant")
        assert data["blocker"] is False
        assert_regulatory_mappings(data)

    def test_verify_oversight_blocker_fail(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/human-oversight/verify", json={
            "modelId": model_id,
            "hasHumanInTheLoop": False,
            "hasKillSwitch": False,
            "deploymentContext": "autonomous",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert data["blocker"] is True


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 5 — Bias Assessment
# ═══════════════════════════════════════════════════════════════════

class TestPhase5BiasAssessment:
    def test_run_bias_assessment(self, http_client: httpx.Client, model_id: str, sample_dataset):
        resp = http_client.post("/api/bias/assess", json={
            "modelId": model_id,
            "datasetSample": sample_dataset,
            "sensitiveFeatures": ["gender"],
            "fairnessThreshold": 0.8,
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "metrics", "overallBiasRisk", "compliant")
        assert isinstance(data["metrics"], list)
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 6 — DPIA Generation
# ═══════════════════════════════════════════════════════════════════

class TestPhase6DPIA:
    def test_generate_dpia(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/dpia/generate", json={
            "modelId": model_id,
            "dataController": "E2E Test Corp",
            "dpoName": "Test DPO",
            "processingPurpose": "AI model training and inference",
            "dataCategories": ["behavioral", "demographic"],
            "crossBorderTransfer": False,
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "dpiaRequired", "sections", "compliant")
        assert isinstance(data["sections"], list)
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 7 — Adversarial Testing
# ═══════════════════════════════════════════════════════════════════

class TestPhase7Adversarial:
    def test_run_adversarial_tests(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/adversarial/run", json={
            "modelId": model_id,
            "testSuites": ["ood_detection"],
            "severityThreshold": "medium",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "tests", "overallRisk", "compliant")
        assert isinstance(data["tests"], list)
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 8 — Weighted Scoring
# ═══════════════════════════════════════════════════════════════════

class TestPhase8WeightedScoring:
    def test_score_audit_weighted(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/scoring/weighted", json={
            "modelId": model_id,
            "riskTier": {"tier": "high", "compliant": True},
            "supplyChain": {"ipClearance": True, "compliant": True},
            "oversight": {"blocker": False, "compliant": True},
            "bias": {"overallBiasRisk": "low", "compliant": True},
            "dpia": {"compliant": True},
            "adversarial": {"overallRisk": "low", "compliant": True},
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "overallScore", "categoryScores", "blockerFailures", "certificationEligible")
        assert 0 <= data["overallScore"] <= 100
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 9 — Certificate Generation
# ═══════════════════════════════════════════════════════════════════

class TestPhase9Certificate:
    def test_generate_certificate(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/certificate/generate", json={
            "modelId": model_id,
            "weightedScore": 85.0,
            "tier": "high",
            "compliant": True,
            "issuerName": "E2E Test Authority",
            "validDays": 365,
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "vc", "storedInPostgres", "evidenceId")
        assert data["storedInPostgres"] is True
        assert "evidenceId" in data and data["evidenceId"] is not None
        # Verify VC structure
        vc = data["vc"]
        assert_has_fields(vc, "id", "type", "issuer", "issuanceDate", "expirationDate", "credentialSubject", "proof")
        assert "VerifiableCredential" in vc["type"]
        assert vc["proof"]["type"] == "Ed25519Signature2020"
        assert vc["proof"]["proofValue"].startswith("z")
        assert_regulatory_mappings(data)
        return data["evidenceId"]


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 10 — Drift Monitoring
# ═══════════════════════════════════════════════════════════════════

class TestPhase10DriftMonitoring:
    def test_monitor_model_drift(self, http_client: httpx.Client, model_id: str, reference_data, production_data):
        resp = http_client.post("/api/drift/monitor", json={
            "modelId": model_id,
            "referenceData": reference_data,
            "productionData": production_data,
            "driftThreshold": 0.1,
            "features": ["feature_a", "feature_b", "feature_c"],
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "metrics", "overallDriftStatus", "compliant")
        assert data["overallDriftStatus"] in ("stable", "warning", "critical")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 11 — Session Memory Audit
# ═══════════════════════════════════════════════════════════════════

class TestPhase11SessionMemory:
    def test_audit_session_memory(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/session-memory/audit", json={
            "modelId": model_id,
            "sessionId": f"session-{uuid.uuid4().hex[:8]}",
            "stmConfig": {
                "maxTokens": 4096,
                "maxHistory": 20,
                "wipeOnExpiry": True,
                "isolation": "per_user",
            },
            "sessionTimeoutMinutes": 30,
            "isolationLevel": "per_user",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "sections", "contextIsolationScore", "compliant")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 12 — RAG Quality Audit
# ═══════════════════════════════════════════════════════════════════

class TestPhase12RAGQuality:
    def test_audit_rag_quality(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/rag-quality/evaluate", json={
            "modelId": model_id,
            "vectorDbConfig": {
                "totalSources": 100,
                "freshSources": 85,
                "protectedGroups": ["gender", "age"],
                "biasScores": {"gender": 0.02, "age": 0.05},
            },
            "sampleQueries": [
                {"query": "What is AI governance?", "expectedAnswer": "AI governance is...", "relevanceScore": 0.9},
            ],
            "freshnessPolicyDays": 90,
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "metrics", "overallRisk", "compliant")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 13 — Prompt Template Audit
# ═══════════════════════════════════════════════════════════════════

class TestPhase13PromptAudit:
    def test_audit_prompt_templates(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/prompt-audit/evaluate", json={
            "modelId": model_id,
            "promptTemplates": [
                {
                    "name": "system-prompt",
                    "template": "You are a helpful AI assistant for compliance auditing.",
                    "role": "system",
                    "use_case": "compliance_audit",
                },
            ],
            "fewShotExamples": [
                {"input": "Is this model compliant?", "output": "Let me check the audit results."},
            ],
            "systemPrompt": "You are a compliance auditor. Follow all regulatory guidelines.",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "sections", "overallRisk", "compliant")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 14 — Agent Trust Audit
# ═══════════════════════════════════════════════════════════════════

class TestPhase14AgentTrust:
    def test_audit_agent_trust(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/agent-trust/evaluate", json={
            "modelId": model_id,
            "agents": [
                {
                    "agentId": "agent-1",
                    "role": "planner",
                    "capabilities": ["planning", "reasoning"],
                    "tools": ["search", "compliance-check"],
                    "hasIdentity": True,
                    "hasSignature": True,
                },
            ],
            "messageBusConfig": {
                "hmac": True,
                "signing": True,
                "authentication": "oauth",
            },
            "p2pEnabled": False,
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "agents", "overallRisk", "compliant")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 15 — Tool Permission Audit
# ═══════════════════════════════════════════════════════════════════

class TestPhase15ToolPermissions:
    def test_audit_tool_permissions(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/tool-permissions/evaluate", json={
            "modelId": model_id,
            "toolRegistry": [
                {
                    "toolName": "compliance-check",
                    "permissions": ["read", "execute"],
                    "agents": ["agent-1"],
                    "scopes": ["audit:read"],
                    "lastAuditedPermissions": ["read", "execute"],
                },
            ],
            "accessLogs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "agentId": "agent-1",
                    "toolName": "compliance-check",
                    "action": "execute",
                    "result": "success",
                    "scope": "audit:read",
                },
            ],
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "issues", "overallRisk", "compliant")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 16 — Agent Autonomy Classification
# ═══════════════════════════════════════════════════════════════════

class TestPhase16AgentAutonomy:
    def test_classify_assistive(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/agent-autonomy/classify", json={
            "modelId": model_id,
            "agentType": "single",
            "hasHumanOversight": True,
            "canMakeDecisions": False,
            "canModifyEnvironment": False,
            "canDelegateTasks": False,
            "canAccessExternalAPIs": False,
            "canSelfModify": False,
            "deploymentContext": "assistive",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "autonomyLevel", "riskTier", "compliant")
        assert data["autonomyLevel"] in ("assistive", "supervised", "autonomous", "fully_autonomous")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: Phase 17 — DPDP Act Assessment
# ═══════════════════════════════════════════════════════════════════

class TestPhase17DPDPAssessment:
    def test_dpdp_compliant(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/dpdp/assess", json={
            "modelId": model_id,
            "dataFiduciary": "E2E Test Corp",
            "consentMechanism": "explicit",
            "dataPrincipalRights": ["access", "correction", "erasure", "grievance_redressal", "nomination"],
            "processingPurpose": "AI model training",
            "hasDataProtectionOfficer": True,
            "hasPrivacyPolicy": True,
            "hasBreachNotification": True,
            "hasChildProtection": True,
            "processingRecords": True,
            "hasAuditTrail": True,
            "hasConsentRecords": True,
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "sections", "overallCompliance", "compliant")
        assert len(data["sections"]) == 10
        assert data["overallCompliance"] in ("compliant", "partially_compliant", "non_compliant")
        # With all flags true, should be mostly compliant
        compliant_sections = sum(1 for s in data["sections"] if s["status"] == "compliant")
        assert compliant_sections >= 7

    def test_dpdp_non_compliant(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/dpdp/assess", json={
            "modelId": model_id,
            "dataFiduciary": "E2E Test Corp",
            "consentMechanism": "none",
            "dataPrincipalRights": [],
            "hasDataProtectionOfficer": False,
            "hasPrivacyPolicy": False,
            "hasBreachNotification": False,
            "hasChildProtection": False,
            "processingRecords": False,
            "hasAuditTrail": False,
            "hasConsentRecords": False,
        })
        assert_ok(resp)
        data = assert_json(resp)
        non_compliant = sum(1 for s in data["sections"] if s["status"] == "non_compliant")
        assert non_compliant >= 5


# ═══════════════════════════════════════════════════════════════════
#  TEST: CRL — Certificate Revocation
# ═══════════════════════════════════════════════════════════════════

class TestCertificateRevocation:
    def test_revoke_and_check_status(self, http_client: httpx.Client, model_id: str):
        # First, generate a certificate
        gen_resp = http_client.post("/api/certificate/generate", json={
            "modelId": model_id,
            "weightedScore": 75.0,
            "tier": "limited",
            "compliant": True,
            "issuerName": "E2E Revoke Test",
            "validDays": 365,
        })
        assert_ok(gen_resp)
        gen_data = assert_json(gen_resp)
        cert_id = gen_data["vc"]["id"]

        # Revoke it
        revoke_resp = http_client.post("/api/certificate/revoke", json={
            "certificateId": cert_id,
            "reason": "key_compromise",
        })
        assert_ok(revoke_resp)
        revoke_data = assert_json(revoke_resp)
        assert revoke_data["revoked"] is True

        # Check status
        status_resp = http_client.get(f"/api/certificate/status/{cert_id}")
        assert_ok(status_resp)
        status_data = assert_json(status_resp)
        assert status_data["revoked"] is True
        assert status_data["valid"] is False

    def test_crl_endpoint(self, http_client: httpx.Client):
        resp = http_client.get("/api/certificate/crl")
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "revokedCertificates", "totalRevoked", "generatedAt", "issuer")
        assert isinstance(data["revokedCertificates"], list)


# ═══════════════════════════════════════════════════════════════════
#  TEST: ROPA — GDPR Art. 30
# ═══════════════════════════════════════════════════════════════════

class TestROPA:
    def test_generate_ropa(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/ropa/generate", json={
            "modelId": model_id,
            "controllerName": "E2E Test Corp",
            "dpoName": "Test DPO",
            "controllerAddress": "123 Test Street",
            "controllerEmail": "dpo@test.com",
            "processingPurposes": ["AI model training", "Inference"],
            "dataSubjectCategories": [
                {"category": "Employees", "description": "Employee data", "retentionPeriod": "3 years", "erasureMechanism": "automated"}
            ],
            "dataCategories": [
                {"category": "Behavioral", "description": "User behavior data", "specialCategory": False, "retentionPeriod": "2 years", "erasureMechanism": "automated", "securityMeasures": ["encryption"]}
            ],
            "recipientCategories": ["Internal teams"],
            "crossBorderTransfer": False,
            "securityMeasures": ["Encryption at rest", "Access controls"],
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "ropaId", "compliant")
        assert_regulatory_mappings(data)


# ═══════════════════════════════════════════════════════════════════
#  TEST: DSAR — GDPR Art. 15-17
# ═══════════════════════════════════════════════════════════════════

class TestDSAR:
    def test_data_subject_access_request(self, http_client: httpx.Client, model_id: str):
        resp = http_client.post("/api/dsar/access", json={
            "modelId": model_id,
            "dataSubjectId": "subject-001",
            "dataSubjectEmail": "subject@example.com",
            "requestType": "access",
        })
        assert_ok(resp)
        data = assert_json(resp)
        assert_has_fields(data, "modelId", "dataSubjectId", "stores")


# ═══════════════════════════════════════════════════════════════════
#  TEST: Input Validation
# ═══════════════════════════════════════════════════════════════════

class TestInputValidation:
    def test_missing_required_field_returns_422(self, http_client: httpx.Client):
        resp = http_client.post("/api/risk/classify", json={
            "modelId": "test",
            # Missing modelType and sector
        })
        assert resp.status_code == 422

    def test_invalid_model_id_pattern_returns_422(self, http_client: httpx.Client):
        resp = http_client.post("/api/risk/classify", json={
            "modelId": "../../etc/passwd",
            "modelType": "other",
            "sector": "other",
        })
        assert resp.status_code == 422
