// ═══════════════════════════════════════════════════════════════════
//  Tool Schemas — Single Source of Truth
//  This file defines all 17 tool input schemas ONCE.
//  Both index.ts (MCP TOOLS) and validator.ts import from here.
//  ANY CHANGE HERE AUTO-PROPAGATES — no manual sync needed.
// ═══════════════════════════════════════════════════════════════════

export interface ToolSchemaEntry {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const MODEL_ID_SCHEMA = {
  type: "string",
  description: "Unique model identifier",
  minLength: 1,
  maxLength: 255,
  pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
} as const;

export const TOOL_SCHEMAS: ToolSchemaEntry[] = [
  // 1. classify_ai_risk
  {
    name: "classify_ai_risk",
    description:
      "Classifies an AI model into an EU AI Act risk tier (Prohibited, High, Limited, Minimal). " +
      "Uses sector context, model type, and profiling capability to determine classification. " +
      "Returns tier with rationale and regulatory article mappings. " +
      "\uD83D\uDD17 EU AI Act Art. 6, Annex I\u2013III | NIST AI RMF MAP 1.1 | ISO/IEC 42001 Clause 6.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { ...MODEL_ID_SCHEMA, description: "Unique model identifier (e.g. 'model-llm-v2')" },
        modelType: {
          type: "string",
          enum: ["general_purpose_ai", "biometric", "critical_infrastructure", "educational", "employment", "credit", "law_enforcement", "other"],
          description: "Category of the AI system per EU AI Act Annex III",
        },
        sector: {
          type: "string",
          enum: ["healthcare", "finance", "criminal_justice", "employment", "education", "critical_infrastructure", "other"],
          description: "Deployment sector for risk context",
        },
        usesProfiling: { type: "boolean", description: "Does the system perform profiling of natural persons?", default: false },
        deployer: { type: "string", description: "Name of the deploying organization", minLength: 1, maxLength: 500 },
      },
      required: ["modelId", "modelType", "sector"],
      additionalProperties: false,
    },
  },

  // 2. discover_supply_chain
  {
    name: "discover_supply_chain",
    description:
      "Automatically discovers ML models and datasets on the filesystem and populates the Neo4j provenance graph. " +
      "Scans configured search paths for model artifacts, checkpoints, and training data. " +
      "\uD83D\uDD17 EU AI Act Art. 10 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        modelSearchPaths: { type: "array", items: { type: "string", minLength: 1 }, description: "Directories to scan for model artifacts", minItems: 0, maxItems: 50, default: [] },
        dataSearchPaths: { type: "array", items: { type: "string", minLength: 1 }, description: "Directories to scan for dataset files", minItems: 0, maxItems: 50, default: [] },
      },
      required: ["modelId"],
      additionalProperties: false,
    },
  },

  // 3. audit_supply_chain
  {
    name: "audit_supply_chain",
    description:
      "Audits the AI model's supply chain via the Neo4j provenance graph. " +
      "Traces data lineage, IP clearance, and third-party dependencies. " +
      "Returns supply chain risk assessment with component-level findings. " +
      "\uD83D\uDD17 EU AI Act Art. 10, 12 | NIST AI RMF GOVERN 1.2 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        deepScan: { type: "boolean", description: "Perform recursive scan of all transitive dependencies", default: false },
      },
      required: ["modelId"],
      additionalProperties: false,
    },
  },

  // 4. verify_human_oversight
  {
    name: "verify_human_oversight",
    description:
      "Verifies human-in-the-loop (HITL) and human-over-the-loop (HOTL) controls. " +
      "Returns a BLOCKER FAIL if kill-switch or oversight mechanisms are absent. " +
      "Required for EU AI Act Art. 14 compliance for high-risk AI systems. " +
      "\uD83D\uDD17 EU AI Act Art. 14 | NIST AI RMF GOVERN 3.2 | ISO/IEC 42001 Clause 8.2 | GDPR Art. 22",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        hasHumanInTheLoop: { type: "boolean", description: "Does the system support human-in-the-loop review of outputs?" },
        hasKillSwitch: { type: "boolean", description: "Does the system have a physical or software kill-switch to halt operations?" },
        oversightProcess: { type: "string", description: "Description of the human oversight process in place", minLength: 1, maxLength: 5000 },
        deploymentContext: { type: "string", enum: ["real_time", "batch", "assistive", "autonomous"], description: "How the system operates in production" },
      },
      required: ["modelId", "hasHumanInTheLoop", "hasKillSwitch", "deploymentContext"],
      additionalProperties: false,
    },
  },

  // 5. run_bias_assessment
  {
    name: "run_bias_assessment",
    description:
      "Runs a multidimensional bias assessment using Fairlearn and AIF360. " +
      "Tests across protected attributes: race, gender, age, disability, socioeconomic status. " +
      "Computes demographic parity, equal opportunity, and disparate impact ratios. " +
      "\uD83D\uDD17 EU AI Act Art. 10 | NIST AI RMF MEASURE 2.2 | ISO/IEC 42001 Clause 8.1.2 | GDPR Art. 9, 35",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        datasetSample: { type: "array", items: { type: "object" }, description: "Array of data samples with labels and protected attributes", minItems: 1 },
        sensitiveFeatures: {
          type: "array",
          items: { type: "string", enum: ["race", "gender", "age", "disability", "socioeconomic_status", "religion", "sexual_orientation", "national_origin"] },
          description: "Protected attributes to test for bias",
          minItems: 1, maxItems: 10, uniqueItems: true,
        },
        fairnessThreshold: { type: "number", description: "Disparate impact ratio threshold (0.0\u20131.0). Default 0.8 per the 80% rule.", minimum: 0.0, maximum: 1.0, default: 0.8 },
      },
      required: ["modelId", "datasetSample", "sensitiveFeatures"],
      additionalProperties: false,
    },
  },

  // 6. generate_dpia
  {
    name: "generate_dpia",
    description:
      "Generates a Data Protection Impact Assessment (DPIA) per GDPR Art. 35. " +
      "Evaluates cross-border transfer mechanisms (Art. 44\u201349) and adequacy decisions. " +
      "Produces structured report with sections on necessity, proportionality, risks, and mitigations. " +
      "\uD83D\uDD17 GDPR Art. 5, 9, 22, 35, 44\u201349 | ISO/IEC 42001 Clause 6.2",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        dataController: { type: "string", description: "Name or legal entity of the data controller (GDPR Art. 4(7))", minLength: 1, maxLength: 500 },
        dpoName: { type: "string", description: "Name of the designated Data Protection Officer (GDPR Art. 37)", minLength: 1, maxLength: 500 },
        processingPurpose: { type: "string", description: "Description of the processing purpose (GDPR Art. 5(1)(b))", minLength: 1, maxLength: 5000 },
        dataCategories: {
          type: "array",
          items: { type: "string", enum: ["biometric", "location", "health", "financial", "behavioral", "demographic", "communication", "genetic", "political", "religious", "other"] },
          description: "Categories of personal data processed (GDPR Art. 9 special categories)",
          minItems: 1, maxItems: 20, uniqueItems: true,
        },
        crossBorderTransfer: { type: "boolean", description: "Does processing involve cross-border data transfer outside EEA?", default: false },
        thirdCountries: { type: "array", items: { type: "string", minLength: 2, maxLength: 3 }, description: "ISO 3166-1 alpha-2/3 country codes", maxItems: 50, default: [] },
      },
      required: ["modelId", "dataController", "dpoName", "processingPurpose", "dataCategories"],
      additionalProperties: false,
    },
  },

  // 7. run_adversarial_tests
  {
    name: "run_adversarial_tests",
    description:
      "Executes adversarial robustness testing: prompt injection, jailbreak attempts, OOD detection, " +
      "model inversion, and membership inference attacks. Each test suite evaluates model resilience " +
      "against specific threat vectors. " +
      "\uD83D\uDD17 EU AI Act Art. 15 | NIST AI RMF MEASURE 1.3 | ISO/IEC 42001 Clause 8.1.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        testSuites: {
          type: "array",
          items: { type: "string", enum: ["prompt_injection", "jailbreak", "ood_detection", "model_inversion", "membership_inference"] },
          description: "Adversarial test suites to execute (minimum 1 required)",
          minItems: 1, maxItems: 5, uniqueItems: true,
        },
        severityThreshold: { type: "string", enum: ["low", "medium", "high"], description: "Minimum severity level to flag as failure", default: "medium" },
      },
      required: ["modelId", "testSuites"],
      additionalProperties: false,
    },
  },

  // 8. score_audit_weighted
  {
    name: "score_audit_weighted",
    description:
      "Aggregates all previous audit phases into a weighted score (0\u2013100). " +
      "**Halts certification** immediately if any BLOCKER FAIL is detected. " +
      "Weights are configurable per organizational policy. " +
      "\uD83D\uDD17 NIST AI RMF MEASURE 4.1 | ISO/IEC 42001 Clause 9.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        riskTier: { type: "object", properties: { tier: { type: "string" }, compliant: { type: "boolean" } }, required: ["tier", "compliant"], description: "Risk classification result" },
        supplyChain: { type: "object", properties: { ipClearance: { type: "boolean" }, compliant: { type: "boolean" } }, required: ["ipClearance", "compliant"], description: "Supply chain audit result" },
        oversight: { type: "object", properties: { blocker: { type: "boolean" }, compliant: { type: "boolean" } }, required: ["blocker", "compliant"], description: "Human oversight result" },
        bias: { type: "object", properties: { overallBiasRisk: { type: "string" }, compliant: { type: "boolean" } }, required: ["overallBiasRisk", "compliant"], description: "Bias assessment result" },
        dpia: { type: "object", properties: { compliant: { type: "boolean" } }, required: ["compliant"], description: "DPIA report result" },
        adversarial: { type: "object", properties: { overallRisk: { type: "string" }, compliant: { type: "boolean" } }, required: ["overallRisk", "compliant"], description: "Adversarial test result" },
      },
      required: ["modelId"],
      additionalProperties: false,
    },
  },

  // 9. generate_audit_certificate
  {
    name: "generate_audit_certificate",
    description:
      "Issues a cryptographically signed W3C Verifiable Credential (VC-JSON) " +
      "for the completed audit. Uses Ed25519Signature2020 suite with multibase encoding. " +
      "Saves to PostgreSQL evidence store with immutable timestamp. " +
      "\uD83D\uDD17 W3C VC Data Model 1.1 | ISO/IEC 42001 Clause 7.5 (Documented Information)",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        weightedScore: { type: "number", description: "Final weighted audit score (0.0\u2013100.0)", minimum: 0.0, maximum: 100.0 },
        tier: { type: "string", enum: ["prohibited", "high", "limited", "minimal", "certified"], description: "Final risk tier or certification level" },
        compliant: { type: "boolean", description: "Overall compliance status (must be true for certification)" },
        issuerName: { type: "string", description: "Name of the issuing authority or governance body", minLength: 1, maxLength: 500 },
        validDays: { type: "number", description: "Validity period in days (default: 365)", minimum: 1, maximum: 3650, default: 365 },
      },
      required: ["modelId", "weightedScore", "tier", "compliant", "issuerName"],
      additionalProperties: false,
    },
  },

  // 10. monitor_model_drift
  {
    name: "monitor_model_drift",
    description:
      "Sets up continuous post-deployment drift monitoring using Evidently AI. " +
      "Computes Population Stability Index (PSI) and Kolmogorov-Smirnov statistics. " +
      "Triggers re-audit workflows via Redis Streams if drift exceeds thresholds. " +
      "\uD83D\uDD17 EU AI Act Art. 15 | NIST AI RMF MEASURE 3.3 | ISO/IEC 42001 Clause 9.1 (Monitoring)",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        referenceData: { type: "array", items: { type: "object" }, description: "Reference/baseline dataset for drift comparison", minItems: 1 },
        productionData: { type: "array", items: { type: "object" }, description: "Current production data for drift evaluation", minItems: 1 },
        driftThreshold: { type: "number", description: "PSI/KS threshold for drift alert (default: 0.1)", minimum: 0.0, maximum: 1.0, default: 0.1 },
        features: { type: "array", items: { type: "string", minLength: 1 }, description: "Feature names to monitor for drift", minItems: 1, maxItems: 200, uniqueItems: true },
      },
      required: ["modelId", "referenceData", "productionData", "features"],
      additionalProperties: false,
    },
  },

  // 11. audit_session_memory
  {
    name: "audit_session_memory",
    description:
      "Audits short-term and long-term memory isolation for AI agents. " +
      "Verifies session data wipe-on-expiry, context window limits, " +
      "and cross-session data leakage prevention. " +
      "\uD83D\uDD17 GDPR Art. 5(1)(f) | GDPR Art. 25 | DPDP Act Sec. 8 | EU AI Act Art. 15",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        sessionId: { type: "string", description: "Session identifier to audit", minLength: 1, maxLength: 255 },
        stmConfig: {
          type: "object",
          description: "Short-term memory configuration",
          properties: {
            maxTokens: { type: "number", minimum: 1, description: "Maximum context window tokens" },
            maxHistory: { type: "number", minimum: 0, description: "Maximum conversation history turns" },
            wipeOnExpiry: { type: "boolean", description: "Whether to wipe data on session expiry" },
            isolation: { type: "string", enum: ["per_user", "per_session", "shared"], description: "Memory isolation strategy" },
          },
          additionalProperties: true,
        },
        ltmConfig: { type: "object", description: "Long-term memory configuration (optional)", additionalProperties: true },
        sessionTimeoutMinutes: { type: "number", description: "Session timeout in minutes (default: 30)", minimum: 1, maximum: 1440, default: 30 },
        isolationLevel: { type: "string", enum: ["per_user", "per_session", "shared"], description: "Memory isolation level", default: "per_user" },
      },
      required: ["modelId", "sessionId", "stmConfig"],
      additionalProperties: false,
    },
  },

  // 12. audit_rag_quality
  {
    name: "audit_rag_quality",
    description:
      "Evaluates RAG pipeline quality: retrieval accuracy, embedding bias, " +
      "knowledge freshness, and hallucination rate. Tests against sample queries " +
      "with expected answers. " +
      "\uD83D\uDD17 EU AI Act Art. 15 | NIST AI RMF MEASURE 3.3 | ISO/IEC 42001 Clause 9.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        vectorDbConfig: {
          type: "object",
          description: "Vector DB configuration",
          properties: {
            totalSources: { type: "number", minimum: 0, description: "Total number of knowledge sources" },
            freshSources: { type: "number", minimum: 0, description: "Sources within freshness policy" },
            protectedGroups: { type: "array", items: { type: "string" }, description: "Protected demographic groups for bias testing" },
            biasScores: { type: "object", description: "Bias scores per protected group" },
          },
          additionalProperties: true,
        },
        sampleQueries: {
          type: "array",
          items: { type: "object", properties: { query: { type: "string" }, expectedAnswer: { type: "string" }, relevanceScore: { type: "number", minimum: 0, maximum: 1 } }, required: ["query", "expectedAnswer"] },
          description: "Sample queries with expected answers",
          minItems: 1,
        },
        freshnessPolicyDays: { type: "number", description: "Knowledge freshness policy in days (default: 90)", minimum: 1, maximum: 3650, default: 90 },
      },
      required: ["modelId", "vectorDbConfig", "sampleQueries"],
      additionalProperties: false,
    },
  },

  // 13. audit_prompt_templates
  {
    name: "audit_prompt_templates",
    description:
      "Audits prompt engineering templates for injection surface, few-shot bias, " +
      "instruction safety, and transparency compliance. " +
      "\uD83D\uDD17 EU AI Act Art. 10, 13 | NIST AI RMF GOVERN 1.2 | ISO/IEC 42001 Clause 8.1.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        promptTemplates: {
          type: "array",
          items: { type: "object", properties: { name: { type: "string", minLength: 1 }, template: { type: "string", minLength: 1 }, role: { type: "string", enum: ["system", "user", "assistant"] }, use_case: { type: "string" } }, required: ["name", "template", "role"] },
          description: "Array of prompt templates to audit",
          minItems: 1,
        },
        fewShotExamples: { type: "array", items: { type: "object", properties: { input: { type: "string" }, output: { type: "string" } }, required: ["input", "output"] }, description: "Few-shot examples to check for bias (optional)" },
        systemPrompt: { type: "string", description: "System prompt to audit for safety and injection risk (optional)", maxLength: 50000 },
      },
      required: ["modelId", "promptTemplates"],
      additionalProperties: false,
    },
  },

  // 14. audit_agent_trust
  {
    name: "audit_agent_trust",
    description:
      "Audits multi-agent trust: identity verification, capability claims validation, " +
      "P2P message integrity, collusion detection, and cross-agent data leakage risk. " +
      "\uD83D\uDD17 EU AI Act Art. 12, 14 | NIST AI RMF GOVERN 1.2 | DPDP Act Sec. 8 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        agents: {
          type: "array",
          items: { type: "object", properties: { agentId: { type: "string", minLength: 1 }, role: { type: "string" }, capabilities: { type: "array", items: { type: "string" } }, tools: { type: "array", items: { type: "string" } }, hasIdentity: { type: "boolean" }, hasSignature: { type: "boolean" } }, required: ["agentId", "role"] },
          description: "Array of agent configurations to audit",
          minItems: 1,
        },
        messageBusConfig: { type: "object", description: "Message bus configuration", properties: { hmac: { type: "boolean" }, signing: { type: "boolean" }, authentication: { type: "string", enum: ["none", "api_key", "mtls", "oauth"] } }, additionalProperties: true },
        p2pEnabled: { type: "boolean", description: "Whether peer-to-peer agent communication is enabled", default: false },
      },
      required: ["modelId", "agents"],
      additionalProperties: false,
    },
  },

  // 15. audit_tool_permissions
  {
    name: "audit_tool_permissions",
    description:
      "Audits tool permission boundaries: verifies agents only access authorized tools, " +
      "detects privilege escalation, unauthorized access, and permission drift. " +
      "\uD83D\uDD17 DPDP Act Sec. 8 | EU AI Act Art. 14 | GDPR Art. 25 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        toolRegistry: {
          type: "array",
          items: { type: "object", properties: { toolName: { type: "string", minLength: 1 }, permissions: { type: "array", items: { type: "string" } }, agents: { type: "array", items: { type: "string" } }, scopes: { type: "array", items: { type: "string" } }, lastAuditedPermissions: { type: "array", items: { type: "string" } } }, required: ["toolName", "permissions", "agents"] },
          description: "Registry of tools and their permission assignments",
          minItems: 1,
        },
        accessLogs: {
          type: "array",
          items: { type: "object", properties: { timestamp: { type: "string" }, agentId: { type: "string" }, toolName: { type: "string" }, action: { type: "string" }, result: { type: "string", enum: ["success", "denied", "error"] }, scope: { type: "string" } }, required: ["timestamp", "agentId", "toolName", "action", "result"] },
          description: "Access logs to audit",
          minItems: 1,
        },
      },
      required: ["modelId", "toolRegistry", "accessLogs"],
      additionalProperties: false,
    },
  },

  // 16. classify_agent_autonomy
  {
    name: "classify_agent_autonomy",
    description:
      "Classifies AI agent autonomy level (assistive/supervised/autonomous/fully_autonomous) " +
      "and maps to EU AI Act risk tiers. Determines required human oversight controls. " +
      "BLOCKER FAIL if fully autonomous without oversight. " +
      "\uD83D\uDD17 EU AI Act Art. 6, 14 | NIST AI RMF GOVERN 3.2 | ISO/IEC 42001 Clause 6.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        agentType: { type: "string", enum: ["single", "multi_agent", "hierarchical", "swarm"], description: "Type of agent architecture" },
        hasHumanOversight: { type: "boolean", description: "Does the agent have human oversight controls?" },
        canMakeDecisions: { type: "boolean", description: "Can the agent make autonomous decisions without human approval?" },
        canModifyEnvironment: { type: "boolean", description: "Can the agent modify its runtime environment?", default: false },
        canDelegateTasks: { type: "boolean", description: "Can the agent delegate tasks to other agents?", default: false },
        canAccessExternalAPIs: { type: "boolean", description: "Can the agent access external APIs or services?", default: false },
        canSelfModify: { type: "boolean", description: "Can the agent modify its own prompts, weights, or configuration?", default: false },
        deploymentContext: { type: "string", enum: ["real_time", "batch", "assistive", "autonomous"], description: "Deployment context", default: "assistive" },
      },
      required: ["modelId", "agentType", "hasHumanOversight", "canMakeDecisions"],
      additionalProperties: false,
    },
  },

  // 17. assess_dpdp_compliance
  {
    name: "assess_dpdp_compliance",
    description:
      "Assesses AI model compliance against the India DPDP Act 2023 (Sec. 5\u201330). " +
      "Evaluates consent mechanisms (Sec. 5/6), fiduciary duties (Sec. 8), " +
      "data principal rights (Sec. 11\u201314), data localization (Sec. 16), " +
      "cross-border transfer (Sec. 16), child protection (Sec. 9), " +
      "significant data fiduciary obligations (Sec. 10), breach notification (Sec. 8(6)), " +
      "and DPO requirements (Sec. 8(9)). " +
      "\uD83D\uDD17 DPDP Act 2023 Sec. 5\u201330 | ISO/IEC 42001 Clause 6.2",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID_SCHEMA,
        dataFiduciary: { type: "string", description: "Name or legal entity of the Data Fiduciary (Sec. 3(8))", minLength: 1, maxLength: 500 },
        consentMechanism: { type: "string", enum: ["explicit", "implied", "opt_out", "none"], description: "Consent mechanism for processing personal data (Sec. 5/6)" },
        dataPrincipalRights: { type: "array", items: { type: "string", enum: ["access", "correction", "erasure", "grievance_redressal", "nomination"] }, minItems: 1, description: "Data principal rights implemented (Sec. 11\u201314)" },
        processingPurpose: { type: "string", description: "Lawful purpose of data processing (Sec. 7)", minLength: 1 },
        dataLocalization: { type: "boolean", description: "Whether personal data is stored only in India (Sec. 16)" },
        crossBorderTransfer: { type: "boolean", description: "Whether cross-border data transfer is permitted (Sec. 16)" },
        transferCountries: { type: "array", items: { type: "string" }, description: "Countries to which data is transferred (Sec. 16)" },
        hasDataProtectionOfficer: { type: "boolean", description: "Whether a Data Protection Officer is appointed (Sec. 8(9))" },
        hasPrivacyPolicy: { type: "boolean", description: "Whether a privacy policy is published (Sec. 8(7))" },
        hasBreachNotification: { type: "boolean", description: "Whether breach notification mechanism exists (Sec. 8(6))" },
        breachNotificationHours: { type: "number", minimum: 1, maximum: 720, description: "Breach notification timeline in hours (Sec. 8(6))" },
        hasChildProtection: { type: "boolean", description: "Whether child data protection measures are implemented (Sec. 9)" },
        hasSignificantDataFiduciaryObligations: { type: "boolean", description: "Whether SDF obligations are met (Sec. 10)" },
        processingRecords: { type: "boolean", description: "Whether processing records are maintained (Sec. 8(7))" },
        dataRetentionDays: { type: "number", minimum: 1, description: "Data retention period in days (Sec. 8(7))" },
        hasConsentRecords: { type: "boolean", description: "Whether consent records are maintained (Sec. 8(8))" },
        hasAuditTrail: { type: "boolean", description: "Whether an audit trail is maintained (Sec. 8(7))" },
      },
      required: ["modelId", "dataFiduciary", "consentMechanism"],
      additionalProperties: false,
    },
  },
];
