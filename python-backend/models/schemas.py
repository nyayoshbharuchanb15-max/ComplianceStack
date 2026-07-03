"""
AI Governance — Pydantic Schemas
─────────────────────────────────
All audit data models with explicit regulatory mappings:

  • EU AI Act (Regulation 2024/1689)
  • NIST AI RMF (NIST AI 100-1)
  • ISO/IEC 42001:2023 (AIMS)
  • GDPR (Regulation 2016/679)

ISO/IEC 42001:2023 Clause 7.5 — All documented information is
retained with versioning and audit trail references.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


# ─── Enums ────────────────────────────────────────────────────────

class RiskTier(str, Enum):
    prohibited = "prohibited"
    high = "high"
    limited = "limited"
    minimal = "minimal"


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class SupplyChainNodeType(str, Enum):
    dataset = "dataset"
    model = "model"
    transform = "transform"
    deployment = "deployment"


class DeploymentContext(str, Enum):
    real_time = "real_time"
    batch = "batch"
    assistive = "assistive"
    autonomous = "autonomous"


class OversightLevel(str, Enum):
    full = "full"
    partial = "partial"
    none_ = "none"


class DriftStatus(str, Enum):
    stable = "stable"
    warning = "warning"
    critical = "critical"


# ─── Phase 1: Risk Classification ─────────────────────────────────

class ClassifyRiskRequest(BaseModel):
    modelId: str
    modelType: str
    sector: str
    usesProfiling: bool = False
    deployer: Optional[str] = None


class RiskTierResult(BaseModel):
    modelId: str
    tier: RiskTier
    rationale: str
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 6",
            "EU AI Act Annex III",
            "NIST AI RMF MAP 1.1",
            "ISO/IEC 42001:2023 Clause 6.1",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 6.1 (Risk Assessment)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 2: Supply Chain Audit ──────────────────────────────────

class AuditSupplyChainRequest(BaseModel):
    modelId: str
    deepScan: bool = False


class ProvenanceRecord(BaseModel):
    nodeId: str
    type: SupplyChainNodeType
    name: str
    version: str
    origin: str
    license: str
    ipCleared: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProvenanceReport(BaseModel):
    modelId: str
    graph: list[ProvenanceRecord]
    supplyChainRisk: RiskLevel
    ipClearance: bool
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 10 (Data Governance)",
            "EU AI Act Art. 12 (Documentation)",
            "NIST AI RMF GOVERN 1.2",
            "ISO/IEC 42001:2023 Clause 7.4.3",
            "GDPR Art. 5(1)(d) (Accuracy of Data)",
            "DPDP Act 2023 Sec. 7 (Duties of Data Fiduciary)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 7.4.3 (Supply Chain)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 3: Human Oversight Verification ────────────────────────

class VerifyHumanOversightRequest(BaseModel):
    modelId: str
    hasHumanInTheLoop: bool
    hasKillSwitch: bool
    oversightProcess: Optional[str] = None
    deploymentContext: DeploymentContext


class OversightCertificate(BaseModel):
    modelId: str
    humanInTheLoop: bool
    killSwitchPresent: bool
    oversightLevel: OversightLevel
    blocker: bool
    remediation: Optional[str] = None
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 14 (Human Oversight)",
            "GDPR Art. 22 (Automated Decision-Making)",
            "NIST AI RMF GOVERN 3.2",
            "ISO/IEC 42001:2023 Clause 8.2",
        ]
    )
    gdprArticles: list[str] = Field(
        default_factory=lambda: [
            "GDPR Art. 22(1): Right not to be subject to automated decisions",
            "GDPR Art. 22(3): Safeguards including human intervention",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 8.2 (Controls)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 4: Bias Assessment ─────────────────────────────────────

class RunBiasAssessmentRequest(BaseModel):
    modelId: str
    datasetSample: list[dict[str, Any]]
    sensitiveFeatures: list[str]
    fairnessThreshold: float = 0.8


class BiasMetric(BaseModel):
    protectedAttribute: str
    metric: str
    score: float
    threshold: float
    passed: bool


class BiasReport(BaseModel):
    modelId: str
    metrics: list[BiasMetric]
    overallBiasRisk: RiskLevel
    sensitiveFeatures: list[str]
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 10 (Bias & Fairness)",
            "GDPR Art. 9 (Special Category Data)",
            "GDPR Art. 35 (DPIA)",
            "NIST AI RMF MEASURE 2.2",
            "ISO/IEC 42001:2023 Clause 8.1.2",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 8.1.2 (Bias Mitigation)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 5: DPIA Generation ─────────────────────────────────────

class GenerateDPIAARequest(BaseModel):
    modelId: str
    dataController: str
    dpoName: str
    processingPurpose: str
    dataCategories: list[str]
    crossBorderTransfer: bool = False
    thirdCountries: list[str] = Field(default_factory=list)


class DPIASection(BaseModel):
    section: str
    finding: str
    risk: RiskLevel
    mitigation: str


class DPIAReport(BaseModel):
    modelId: str
    dpiaRequired: bool
    dataController: str
    dataProtectionOfficer: str
    sections: list[DPIASection]
    crossBorderTransfer: bool
    adequacyDecision: Optional[str] = None
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "GDPR Art. 5 (Principles)",
            "GDPR Art. 9 (Special Categories)",
            "GDPR Art. 22 (Automated Decisions)",
            "GDPR Art. 35 (DPIA)",
            "GDPR Art. 44–49 (Cross-Border Transfers)",
            "ISO/IEC 42001:2023 Clause 6.2",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 6.2 (Data Protection)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 6: Adversarial Testing ─────────────────────────────────

class RunAdversarialTestsRequest(BaseModel):
    modelId: str
    testSuites: list[str]
    severityThreshold: str = "medium"
    endpoint_url: Optional[str] = None
    api_key: Optional[str] = None
    target_model: Optional[str] = None
    judge_model: Optional[str] = None
    embedding_model: Optional[str] = None


class AdversarialTestResult(BaseModel):
    testName: str
    passed: bool
    severity: RiskLevel
    details: str


class AdversarialReport(BaseModel):
    modelId: str
    tests: list[AdversarialTestResult]
    overallRisk: RiskLevel
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 15 (Accuracy & Robustness)",
            "NIST AI RMF MEASURE 1.3",
            "ISO/IEC 42001:2023 Clause 8.1.3",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 8.1.3 (Adversarial Testing)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 7: Weighted Scoring ────────────────────────────────────

class ScoreAuditWeightedRequest(BaseModel):
    modelId: str
    riskTier: Optional[dict[str, Any]] = None
    supplyChain: Optional[dict[str, Any]] = None
    oversight: Optional[dict[str, Any]] = None
    bias: Optional[dict[str, Any]] = None
    dpia: Optional[dict[str, Any]] = None
    adversarial: Optional[dict[str, Any]] = None


class WeightedAuditScore(BaseModel):
    modelId: str
    overallScore: float = Field(ge=0, le=100)
    categoryScores: dict[str, float]
    blockerFailures: list[str]
    certificationEligible: bool
    summary: str
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "NIST AI RMF MEASURE 4.1",
            "ISO/IEC 42001:2023 Clause 9.1 (Evaluation)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 9.1 (Audit Scoring)"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 8: Certificate Generation ──────────────────────────────

class GenerateCertificateRequest(BaseModel):
    modelId: str
    weightedScore: float
    tier: str
    compliant: bool
    issuerName: str
    validDays: int = 365


class VerifiableCredentialProof(BaseModel):
    type: str = "Ed25519Signature2020"
    created: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verificationMethod: str
    proofPurpose: str = "assertionMethod"
    proofValue: str


class VerifiableCredential(BaseModel):
    context: list[str] = Field(
        default_factory=lambda: [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        alias="@context",
    )
    id: str
    type: list[str] = Field(
        default_factory=lambda: [
            "VerifiableCredential",
            "AIAuditCertificate",
        ]
    )
    issuer: dict[str, str]
    issuanceDate: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expirationDate: str
    credentialSubject: dict[str, Any]
    proof: VerifiableCredentialProof


class AuditCertificate(BaseModel):
    modelId: str
    vc: VerifiableCredential
    storedInPostgres: bool
    evidenceId: str
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "W3C VC Data Model 1.1",
            "ISO/IEC 42001:2023 Clause 7.5 (Documented Information)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 7.5 (Audit Certificate)"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 9: Drift Monitoring ────────────────────────────────────

class FeatureDriftConfig(BaseModel):
    feature: str
    stattest: Optional[str] = None       # ks, jensenshannon, wasserstein, anderson, etc.
    threshold: Optional[float] = None    # overrides the global drift_threshold


class EmbeddingDriftConfig(BaseModel):
    embedding_name: str
    columns: list[str]                   # column names forming the embedding vector


class DriftDetectionConfig(BaseModel):
    features: Optional[list[FeatureDriftConfig]] = None
    embeddings: Optional[list[EmbeddingDriftConfig]] = None
    default_stattest: str = "ks"
    drift_threshold: float = 0.1


class MonitorDriftRequest(BaseModel):
    modelId: str
    referenceData: list[dict[str, Any]]
    productionData: list[dict[str, Any]]
    driftThreshold: float = 0.1
    features: list[str]
    driftConfig: Optional[DriftDetectionConfig] = None


class DriftMetric(BaseModel):
    feature: str
    driftScore: float
    threshold: float
    drifted: bool


class DriftReport(BaseModel):
    modelId: str
    metrics: list[DriftMetric]
    overallDriftStatus: DriftStatus
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 15 (Ongoing Monitoring)",
            "NIST AI RMF MEASURE 3.3",
            "ISO/IEC 42001:2023 Clause 9.1 (Monitoring)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 9.1 (Post-Deployment Monitoring)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── India DPDP Act 2023 ─────────────────────────────────────────

class DPDPConsentRequest(BaseModel):
    modelId: str
    dataFiduciary: str
    dataProcessor: Optional[str] = None
    processingPurpose: str
    dataCategories: list[str]
    consentType: str = "explicit"  # explicit, deemed, or withdraw
    noticeProvided: bool = False
    consentMechanism: str = ""     # description of consent collection mechanism


class DPDPConsentRecord(BaseModel):
    modelId: str
    consentId: str
    dataFiduciary: str
    dataProcessor: Optional[str]
    purpose: str
    dataCategories: list[str]
    consentType: str
    consentGiven: bool
    timestamp: str
    validUntil: str
    withdrawable: bool
    mappedSections: list[str] = Field(
        default_factory=lambda: [
            "DPDP Act 2023 Sec. 5 (Consent)",
            "DPDP Act 2023 Sec. 6 (Deemed Consent)",
            "DPDP Act 2023 Sec. 7 (Duties of Data Fiduciary)",
        ]
    )
    compliant: bool


class DPDPSection(BaseModel):
    section: str
    requirement: str
    status: str          # compliant, partially_compliant, non_compliant
    finding: str
    remediation: str


class DPDPComplianceReport(BaseModel):
    modelId: str
    dataFiduciary: str
    dataProcessor: Optional[str]
    sections: list[DPDPSection]
    overallCompliance: str  # compliant, partially_compliant, non_compliant
    consentRecords: list[DPDPConsentRecord]
    hasDataProtectionOfficer: bool
    hasDPIA: bool
    hasDataAudit: bool
    crossBorderTransferCompliant: bool
    mappedSections: list[str] = Field(
        default_factory=lambda: [
            "DPDP Act 2023 Sec. 5 (Consent)",
            "DPDP Act 2023 Sec. 6 (Deemed Consent)",
            "DPDP Act 2023 Sec. 7 (Duties of Data Fiduciary)",
            "DPDP Act 2023 Sec. 8 (Duties of Data Processor)",
            "DPDP Act 2023 Sec. 9 (Additional Obligations)",
            "DPDP Act 2023 Sec. 10 (Rights of Data Principal)",
            "DPDP Act 2023 Sec. 11 (Right to Update)",
            "DPDP Act 2023 Sec. 12 (Right to Erasure)",
            "DPDP Act 2023 Sec. 13 (Grievance Redressal)",
            "DPDP Act 2023 Sec. 14 (Data Protection Officer)",
        ]
    )
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DPDPSummaryRequest(BaseModel):
    modelId: str
    dataFiduciary: str
    consentMechanism: str = "explicit"     # explicit, implied, opt_out, none
    dataPrincipalRights: list[str] = Field(default_factory=list)  # access, correction, erasure, grievance_redressal, nomination
    processingPurpose: str = ""
    dataLocalization: bool = False
    crossBorderTransfer: bool = False
    transferCountries: list[str] = Field(default_factory=list)
    hasDataProtectionOfficer: bool = False
    hasPrivacyPolicy: bool = False
    hasBreachNotification: bool = False
    breachNotificationHours: int = 72
    hasChildProtection: bool = False
    hasSignificantDataFiduciaryObligations: bool = False
    processingRecords: bool = False
    dataRetentionDays: int = 365
    hasConsentRecords: bool = False
    hasAuditTrail: bool = False


# ─── GDPR Art. 30: Record of Processing Activities ────────────────

class ROPADataSubjectCategory(BaseModel):
    category: str
    description: str
    retentionPeriod: str
    erasureMechanism: str


class ROPADataCategory(BaseModel):
    category: str
    description: str
    specialCategory: bool = False
    retentionPeriod: str
    erasureMechanism: str
    securityMeasures: list[str]


class GenerateROPARequest(BaseModel):
    modelId: str
    controllerName: str
    controllerRepresentative: Optional[str] = None
    dpoName: Optional[str] = None
    controllerAddress: str
    controllerEmail: str
    jointControllers: list[str] = []
    processingPurposes: list[str]
    dataSubjectCategories: list[ROPADataSubjectCategory]
    dataCategories: list[ROPADataCategory]
    recipientCategories: list[str]
    crossBorderTransfer: bool = False
    thirdCountries: list[str] = []
    transferSafeguards: list[str] = []
    retentionScheduleDescription: str = ""
    securityMeasures: list[str] = []


class ROPAReport(BaseModel):
    modelId: str
    controllerName: str
    controllerRepresentative: Optional[str] = None
    dpoName: Optional[str] = None
    controllerAddress: str
    controllerEmail: str
    jointControllers: list[str]
    processingPurposes: list[str]
    dataSubjectCategories: list[ROPADataSubjectCategory]
    dataCategories: list[ROPADataCategory]
    recipientCategories: list[str]
    crossBorderTransfer: bool
    thirdCountries: list[str]
    transferSafeguards: list[str]
    retentionScheduleDescription: str
    securityMeasures: list[str]
    ropaId: str
    compliant: bool
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "GDPR Art. 30 (Record of Processing Activities)",
            "GDPR Art. 5(2) (Accountability)",
            "ISO/IEC 42001:2023 Clause 7.5 (Documented Information)",
            "EU AI Act Art. 12 (Technical Documentation)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 7.5 (Documented Information)"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── GDPR Art. 15–17: Data Subject Rights (DSAR / Erasure) ───────

class DSARRequest(BaseModel):
    modelId: str
    dataSubjectId: str
    dataSubjectEmail: str
    requestType: str = "access"           # access, rectification, erasure
    requestDetails: str = ""


class ErasureStoreStatus(BaseModel):
    store: str
    status: str                           # pending, completed, skipped, failed
    recordsDeleted: int = 0
    error: Optional[str] = None


class ErasureProof(BaseModel):
    leafHash: str
    merkleRoot: str
    proof: list[dict[str, str]]


class DSARResponse(BaseModel):
    modelId: str
    dataSubjectId: str
    requestType: str
    requestId: str
    compliant: bool
    stores: list[ErasureStoreStatus]
    erasureProof: Optional[ErasureProof] = None
    erasureCertificate: Optional[VerifiableCredential] = None
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "GDPR Art. 15 (Right of Access)",
            "GDPR Art. 17 (Right to Erasure)",
            "GDPR Art. 5(1)(e) (Storage Limitation)",
            "ISO/IEC 42001:2023 Clause 7.5 (Documented Information)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 7.5 (Erasure Audit Trail)"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Health Check ─────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    services: dict[str, str]


# ─── Agent Workflow Auditing: Session Memory ─────────────────────

class AuditSessionMemoryRequest(BaseModel):
    modelId: str
    sessionId: str
    stmConfig: dict[str, Any]
    ltmConfig: Optional[dict[str, Any]] = None
    sessionTimeoutMinutes: int = 30
    isolationLevel: str = "per_user"


class SessionMemorySection(BaseModel):
    section: str
    requirement: str
    status: str
    finding: str
    remediation: str


class SessionMemoryReport(BaseModel):
    modelId: str
    sessionId: str
    sections: list[SessionMemorySection]
    contextIsolationScore: float
    memoryRetentionCompliant: bool
    wipeOnExpiryVerified: bool
    overallRisk: RiskLevel
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "GDPR Art. 5(1)(f) (Integrity & Confidentiality)",
            "GDPR Art. 25 (Data Protection by Design)",
            "DPDP Act 2023 Sec. 8 (Processor Duties)",
            "EU AI Act Art. 15 (Accuracy & Monitoring)",
            "ISO/IEC 42001:2023 Clause 8.2 (Controls)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 8.2 (Memory Isolation Controls)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Agent Workflow Auditing: RAG Quality ────────────────────────

class AuditRAGQualityRequest(BaseModel):
    modelId: str
    vectorDbConfig: dict[str, Any]
    sampleQueries: list[dict[str, Any]]
    freshnessPolicyDays: int = 90


class RAGQualityMetric(BaseModel):
    metric: str
    score: float
    threshold: float
    passed: bool
    details: str


class RAGQualityReport(BaseModel):
    modelId: str
    metrics: list[RAGQualityMetric]
    overallRisk: RiskLevel
    retrievalAccuracy: float
    embeddingBiasDetected: bool
    knowledgeFreshnessScore: float
    hallucinationRate: float
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 15 (Accuracy)",
            "NIST AI RMF MEASURE 3.3 (Monitoring)",
            "ISO/IEC 42001:2023 Clause 9.1 (Performance Evaluation)",
            "EU AI Act Art. 10 (Data Quality)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 9.1 (RAG Performance)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Agent Workflow Auditing: Prompt Template Audit ──────────────

class AuditPromptTemplatesRequest(BaseModel):
    modelId: str
    promptTemplates: list[dict[str, Any]]
    fewShotExamples: Optional[list[dict[str, Any]]] = None
    systemPrompt: Optional[str] = None


class PromptTemplateSection(BaseModel):
    templateName: str
    section: str
    status: str
    finding: str
    remediation: str


class PromptAuditReport(BaseModel):
    modelId: str
    sections: list[PromptTemplateSection]
    overallRisk: RiskLevel
    injectionSurfaceScore: float
    fewShotBiasDetected: bool
    instructionSafetyScore: float
    transparencyCompliant: bool
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 10 (Data Quality)",
            "EU AI Act Art. 13 (Transparency)",
            "NIST AI RMF GOVERN 1.2 (Supply Chain)",
            "ISO/IEC 42001:2023 Clause 8.1.3 (Adversarial Resilience)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 8.1.3 (Prompt Safety)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Agent Workflow Auditing: Agent Trust & Identity ─────────────

class AuditAgentTrustRequest(BaseModel):
    modelId: str
    agents: list[dict[str, Any]]
    messageBusConfig: Optional[dict[str, Any]] = None
    p2pEnabled: bool = False


class AgentTrustRecord(BaseModel):
    agentId: str
    role: str
    identityVerified: bool
    capabilityClaimsValid: bool
    messageIntegritySupported: bool
    trustScore: float
    issues: list[str]


class AgentTrustReport(BaseModel):
    modelId: str
    agents: list[AgentTrustRecord]
    overallRisk: RiskLevel
    crossAgentLeakageRisk: float
    messageBusIntegrity: bool
    collusionRisk: RiskLevel
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 14 (Human Oversight)",
            "EU AI Act Art. 12 (Technical Documentation)",
            "NIST AI RMF GOVERN 1.2 (Supply Chain)",
            "DPDP Act 2023 Sec. 8 (Processor Duties)",
            "ISO/IEC 42001:2023 Clause 7.4.3 (Supply Chain)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 7.4.3 (Agent Trust)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Agent Workflow Auditing: Tool Permission Boundaries ─────────

class AuditToolPermissionsRequest(BaseModel):
    modelId: str
    toolRegistry: list[dict[str, Any]]
    accessLogs: list[dict[str, Any]]


class ToolPermissionIssue(BaseModel):
    toolName: str
    issueType: str
    severity: RiskLevel
    finding: str
    remediation: str


class ToolPermissionReport(BaseModel):
    modelId: str
    issues: list[ToolPermissionIssue]
    overallRisk: RiskLevel
    privilegeEscalationDetected: bool
    unauthorizedAccessCount: int
    permissionDriftCount: int
    principleOfLeastPrivilege: bool
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "DPDP Act 2023 Sec. 8 (Processor Duties)",
            "EU AI Act Art. 14 (Human Oversight)",
            "GDPR Art. 25 (Data Protection by Design)",
            "ISO/IEC 42001:2023 Clause 7.4.3 (Supply Chain)",
            "NIST AI RMF GOVERN 1.2 (Supply Chain)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 7.4.3 (Tool Permissions)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Agent Workflow Auditing: Autonomy Classification ────────────

class AutonomyLevel(str, Enum):
    assistive = "assistive"
    supervised = "supervised"
    autonomous = "autonomous"
    fully_autonomous = "fully_autonomous"


class ClassifyAgentAutonomyRequest(BaseModel):
    modelId: str
    agentType: str
    hasHumanOversight: bool
    canMakeDecisions: bool
    canModifyEnvironment: bool = False
    canDelegateTasks: bool = False
    canAccessExternalAPIs: bool = False
    canSelfModify: bool = False
    deploymentContext: str = "assistive"


class AgentAutonomyResult(BaseModel):
    modelId: str
    autonomyLevel: AutonomyLevel
    agentType: str
    riskTier: RiskTier
    rationale: str
    humanOversightRequired: bool
    recommendedControls: list[str]
    mappedArticles: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 6 (Risk Tiering)",
            "EU AI Act Art. 14 (Human Oversight)",
            "NIST AI RMF GOVERN 3.2 (Oversight)",
            "ISO/IEC 42001:2023 Clause 6.1 (Risk Assessment)",
        ]
    )
    iso42001Clause: str = "ISO/IEC 42001:2023 Clause 6.1 (Autonomy Risk)"
    compliant: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
