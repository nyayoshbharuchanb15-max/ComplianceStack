// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nyayosh Bharuchanb15-Max

// ─── ComplianceStack MCP Server — Shared Types ──────────────────────
// ISO/IEC 42001:2023 Clause 6.3 — All audit artifacts are versioned
// and traceable to regulatory frameworks.

/** EU AI Act risk tier classification (Art. 6, Annex I–III) */
export type RiskTier = "prohibited" | "high" | "limited" | "minimal";

export interface RiskTierResult {
  modelId: string;
  tier: RiskTier;
  rationale: string;
  mappedArticles: string[];       // e.g. ["EU AI Act Art. 6(2)", "EU AI Act Annex III"]
  iso42001Clause: string;         // e.g. "ISO/IEC 42001:2023 Clause 6.1"
  compliant: boolean;
  timestamp: string;
}

export interface ProvenanceRecord {
  nodeId: string;
  type: "dataset" | "model" | "transform" | "deployment";
  name: string;
  version: string;
  origin: string;
  license: string;
  ipCleared: boolean;
  timestamp: string;
}

export interface ProvenanceReport {
  modelId: string;
  graph: ProvenanceRecord[];
  supplyChainRisk: "low" | "medium" | "high" | "critical";
  ipClearance: boolean;
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

export interface OversightCertificate {
  modelId: string;
  humanInTheLoop: boolean;
  killSwitchPresent: boolean;
  oversightLevel: "full" | "partial" | "none";
  blocker: boolean;               // true → BLOCKER FAIL
  remediation: string | null;
  mappedArticles: string[];       // EU AI Act Art. 14
  gdprArticles: string[];         // GDPR Art. 22
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

export interface BiasMetric {
  protectedAttribute: string;
  metric: string;                 // e.g. "demographic_parity", "equal_opportunity"
  score: number;
  threshold: number;
  passed: boolean;
}

export interface BiasReport {
  modelId: string;
  metrics: BiasMetric[];
  overallBiasRisk: "low" | "medium" | "high" | "critical";
  sensitiveFeatures: string[];
  mappedArticles: string[];       // EU AI Act Art. 10, GDPR Art. 9, 35
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

export interface DPIASection {
  section: string;
  finding: string;
  risk: "low" | "medium" | "high";
  mitigation: string;
}

export interface DPIAReport {
  modelId: string;
  dpiaRequired: boolean;          // GDPR Art. 35(1)
  dataController: string;
  dataProtectionOfficer: string;
  sections: DPIASection[];
  crossBorderTransfer: boolean;   // GDPR Art. 44–49
  adequacyDecision: string | null;
  mappedArticles: string[];       // GDPR Art. 5, 9, 22, 35, 44
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

export interface AdversarialTest {
  testName: string;               // "prompt_injection", "ood_detection", "jailbreak"
  passed: boolean;
  severity: "low" | "medium" | "high" | "critical";
  details: string;
}

export interface AdversarialReport {
  modelId: string;
  tests: AdversarialTest[];
  overallRisk: "low" | "medium" | "high" | "critical";
  mappedArticles: string[];       // EU AI Act Art. 15, ISO/IEC 42001 Clause 8.1
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

export interface WeightedAuditScore {
  modelId: string;
  overallScore: number;           // 0–100
  categoryScores: Record<string, number>;
  blockerFailures: string[];      // Non-empty → halt certification
  certificationEligible: boolean;
  compliant: boolean;
  summary: string;
  mappedArticles: string[];
  iso42001Clause: string;
  timestamp: string;
}

/** W3C Verifiable Credential (VC-JSON) compliant data model */
export interface VerifiableCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: { id: string; name: string };
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: {
    id: string;
    modelId: string;
    auditScore: number;
    tier: string;
    compliant: boolean;
  };
  proof: {
    type: string;                 // "Ed25519Signature2020"
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;           // base58 multibase signature
  };
}

export interface AuditCertificate {
  modelId: string;
  vc: VerifiableCredential;
  compliant: boolean;
  storedInPostgres: boolean;
  evidenceId: string;             // UUID reference in PostgreSQL evidence store
  mappedArticles: string[];
  iso42001Clause: string;
  timestamp: string;
}

export interface DriftMetric {
  feature: string;
  driftScore: number;
  threshold: number;
  drifted: boolean;
}

export interface DriftReport {
  modelId: string;
  metrics: DriftMetric[];
  overallDriftStatus: "stable" | "warning" | "critical";
  mappedArticles: string[];       // ISO/IEC 42001 Clause 9.1, EU AI Act Art. 15
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── Data Discovery ─────────────────────────────────────────────

export interface DiscoveryResult {
  modelId: string;
  datasetsDiscovered: number;
  artifactsDiscovered: number;
  graphPopulated: boolean;
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── India DPDP Act 2023 ────────────────────────────────────────

export interface DPDPSection {
  section: string;
  requirement: string;
  status: "compliant" | "partially_compliant" | "non_compliant";
  finding: string;
  remediation: string;
}

export interface DPDPComplianceReport {
  modelId: string;
  dataFiduciary: string;
  consentMechanism: "explicit" | "implied" | "opt_out" | "none";
  dataPrincipalRights: string[];
  processingPurpose: string;
  dataLocalization: boolean;
  crossBorderTransfer: boolean;
  transferCountries: string[];
  hasDataProtectionOfficer: boolean;
  hasPrivacyPolicy: boolean;
  hasBreachNotification: boolean;
  breachNotificationHours: number;
  hasChildProtection: boolean;
  hasSignificantDataFiduciaryObligations: boolean;
  processingRecords: boolean;
  dataRetentionDays: number;
  hasConsentRecords: boolean;
  hasAuditTrail: boolean;
  sections: DPDPSection[];
  overallCompliance: "compliant" | "partially_compliant" | "non_compliant";
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── Agent Workflow Auditing: Session Memory ─────────────────────

export interface SessionMemorySection {
  section: string;
  requirement: string;
  status: string;
  finding: string;
  remediation: string;
}

export interface SessionMemoryReport {
  modelId: string;
  sessionId: string;
  sections: SessionMemorySection[];
  contextIsolationScore: number;
  memoryRetentionCompliant: boolean;
  wipeOnExpiryVerified: boolean;
  overallRisk: "low" | "medium" | "high" | "critical";
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── Agent Workflow Auditing: RAG Quality ────────────────────────

export interface RAGQualityMetric {
  metric: string;
  score: number;
  threshold: number;
  passed: boolean;
  details: string;
}

export interface RAGQualityReport {
  modelId: string;
  metrics: RAGQualityMetric[];
  overallRisk: "low" | "medium" | "high" | "critical";
  retrievalAccuracy: number;
  embeddingBiasDetected: boolean;
  knowledgeFreshnessScore: number;
  hallucinationRate: number;
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── Agent Workflow Auditing: Prompt Template Audit ──────────────

export interface PromptTemplateSection {
  templateName: string;
  section: string;
  status: string;
  finding: string;
  remediation: string;
}

export interface PromptAuditReport {
  modelId: string;
  sections: PromptTemplateSection[];
  overallRisk: "low" | "medium" | "high" | "critical";
  injectionSurfaceScore: number;
  fewShotBiasDetected: boolean;
  instructionSafetyScore: number;
  transparencyCompliant: boolean;
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── Agent Workflow Auditing: Agent Trust & Identity ─────────────

export interface AgentTrustRecord {
  agentId: string;
  role: string;
  identityVerified: boolean;
  capabilityClaimsValid: boolean;
  messageIntegritySupported: boolean;
  trustScore: number;
  issues: string[];
}

export interface AgentTrustReport {
  modelId: string;
  agents: AgentTrustRecord[];
  overallRisk: "low" | "medium" | "high" | "critical";
  crossAgentLeakageRisk: number;
  messageBusIntegrity: boolean;
  collusionRisk: "low" | "medium" | "high" | "critical";
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── Agent Workflow Auditing: Tool Permission Boundaries ─────────

export interface ToolPermissionIssue {
  toolName: string;
  issueType: string;
  severity: "low" | "medium" | "high" | "critical";
  finding: string;
  remediation: string;
}

export interface ToolPermissionReport {
  modelId: string;
  issues: ToolPermissionIssue[];
  overallRisk: "low" | "medium" | "high" | "critical";
  privilegeEscalationDetected: boolean;
  unauthorizedAccessCount: number;
  permissionDriftCount: number;
  principleOfLeastPrivilege: boolean;
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}

// ─── Agent Workflow Auditing: Autonomy Classification ────────────

export type AutonomyLevel = "assistive" | "supervised" | "autonomous" | "fully_autonomous";

export interface AgentAutonomyResult {
  modelId: string;
  autonomyLevel: AutonomyLevel;
  agentType: string;
  riskTier: "prohibited" | "high" | "limited" | "minimal";
  rationale: string;
  humanOversightRequired: boolean;
  recommendedControls: string[];
  mappedArticles: string[];
  iso42001Clause: string;
  compliant: boolean;
  timestamp: string;
}
