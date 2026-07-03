// ═══════════════════════════════════════════════════════════════════
//  ComplianceStack MCP Server — Complete Implementation
//  Exposes 17 audit tools via the Model Context Protocol SDK.
//  Connected to Python FastAPI Backend for all audit logic.
//  ================================================================

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { callPythonBackend } from "./client.js";
import type {
  RiskTierResult,
  ProvenanceReport,
  OversightCertificate,
  BiasReport,
  DPIAReport,
  AdversarialReport,
  WeightedAuditScore,
  AuditCertificate,
  DriftReport,
  DiscoveryResult,
  DPDPComplianceReport,
  SessionMemoryReport,
  RAGQualityReport,
  PromptAuditReport,
  AgentTrustReport,
  ToolPermissionReport,
  AgentAutonomyResult,
} from "./types.js";

// ─── Response Formatter ──────────────────────────────────────────

function formatSuccess(result: unknown, label: string) {
  return {
    content: [
      {
        type: "text",
        text: `📋 ${label} Result:\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``,
      },
    ],
  };
}

// ─── MCP Server Instance ─────────────────────────────────────────

const server = new Server(
  {
    name: "compliance-stack-mcp-server",
    version: "2.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

// ─── Tool Schemas ─────────────────────────────────────────────────

const TOOLS = [
  {
    name: "assess_dpdp_compliance",
    description:
      "Assesses AI model compliance against the India DPDP Act 2023 (Sec. 5–14). " +
      "Evaluates consent mechanisms, fiduciary duties, data principal rights, and DPO requirements. " +
      "🔗 DPDP Act 2023 | ISO/IEC 42001 Clause 6.2",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        dataFiduciary: { type: "string", description: "Name/entity of the Data Fiduciary" },
      },
      required: ["modelId", "dataFiduciary"],
    },
  },
  {
    name: "discover_supply_chain",
    description:
      "Automatically discovers ML models and datasets on the filesystem and populates the Neo4j provenance graph. " +
      "🔗 EU AI Act Art. 10 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        modelSearchPaths: {
          type: "array",
          items: { type: "string" },
          description: "Optional directories to scan for model artifacts",
        },
        dataSearchPaths: {
          type: "array",
          items: { type: "string" },
          description: "Optional directories to scan for dataset files",
        },
      },
      required: ["modelId"],
    },
  },
  {
    name: "classify_ai_risk",
    description:
      "Classifies an AI model into an EU AI Act risk tier (Prohibited, High, Limited, Minimal). " +
      "🔗 EU AI Act Art. 6, Annex I–III | NIST AI RMF MAP 1.1 | ISO/IEC 42001 Clause 6.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier (e.g. 'model-llm-v2')" },
        modelType: {
          type: "string",
          enum: ["general_purpose_ai", "biometric", "critical_infrastructure", "educational", "employment", "credit", "law_enforcement", "other"],
          description: "Category of the AI system per EU AI Act Annex III",
        },
        sector: {
          type": "string",
          enum: ["healthcare", "finance", "criminal_justice", "employment", "education", "critical_infrastructure", "other"],
          description: "Deployment sector for risk context",
        },
        usesProfiling: { type: "boolean", description: "Does the system perform profiling of natural persons?" },
        deployer: { type: "string", description: "Name of the deploying organization" },
      },
      required: ["modelId", "modelType", "sector"],
    },
  },
  {
    name: "audit_supply_chain",
    description:
      "Audits the AI model's supply chain via the Neo4j provenance graph. " +
      "Traces data lineage, IP clearance, and third-party dependencies. " +
      "🔗 EU AI Act Art. 10, 12 | NIST AI RMF GOVERN 1.2 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        deepScan: {
          type: "boolean",
          description: "Perform recursive scan of all transitive dependencies",
          default: false,
        },
      },
      required: ["modelId"],
    },
  },
  {
    name: "verify_human_oversight",
    description:
      "Verifies human-in-the-loop (HITL) and human-over-the-loop (HOTL) controls. " +
      "Returns a BLOCKER FAIL if kill-switch or oversight mechanisms are absent. " +
      "🔗 EU AI Act Art. 14 | NIST AI RMF GOVERN 3.2 | ISO/IEC 42001 Clause 8.2 | GDPR Art. 22",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        hasHumanInTheLoop: { type: "boolean", description: "Does the system support HITL review?" },
        hasKillSwitch: { type": "boolean", description: "Does the system have a physical/software kill-switch?" },
        oversightProcess: {
          type: "string",
          description: "Description of the human oversight process in place",
        },
        deploymentContext: {
          type: "string",
          enum: ["real_time", "batch", "assistive", "autonomous"],
          description: "How the system operates in practice",
        },
      },
      required: ["modelId", "hasHumanInTheLoop", "hasKillSwitch", "deploymentContext"],
    },
  },
  {
    name: "run_bias_assessment",
    description:
      "Runs a multidimensional bias assessment using Fairlearn and AIF360. " +
      "Tests across protected attributes: race, gender, age, disability, socioeconomic status. " +
      "🔗 EU AI Act Art. 10 | NIST AI RMF MEASURE 2.2 | ISO/IEC 42001 Clause 8.1.2 | GDPR Art. 9, 35",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        datasetSample: {
          type: "array",
          items: { type: "object" },
          description: "Array of data samples with labels and protected attributes for bias analysis",
        },
        sensitiveFeatures: {
          type: "array",
          items: { type: "string" },
          description: "List of protected attributes to test (e.g. ['race', 'gender', 'age'])",
        },
        fairnessThreshold: {
          type": "number",
          description: "Disparate impact ratio threshold (default: 0.8 per 80% rule)",
          default: 0.8,
        },
      },
      required: ["modelId", "datasetSample", "sensitiveFeatures"],
    },
  },
  {
    name: "generate_dpia",
    description:
      "Generates a Data Protection Impact Assessment (DPIA) per GDPR Art. 35. " +
      "Evaluates cross-border transfer mechanisms (Art. 44–49) and adequacy decisions. " +
      "🔗 GDPR Art. 5, 9, 22, 35, 44–49 | ISO/IEC 42001 Clause 6.2",
    inputSchema: {
      type": "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        dataController: { type: "string", description: "Name/entity of the data controller" },
        dpoName: { type: "string", description: "Name of the Data Protection Officer" },
        processingPurpose: { type: "string", description: "Description of the processing purpose" },
        dataCategories: {
          type: "array",
          items: { type: "string" },
          description: "Categories of personal data processed (e.g. ['biometric', 'location', 'health'])",
        },
        crossBorderTransfer: {
          type: "boolean",
          description: "Does processing involve cross-border data transfer?",
        },
        thirdCountries: {
          type: "array",
          items: { type: "string" },
          description: "List of third countries involved in transfers",
        },
      },
      required: ["modelId", "dataController", "dpoName", "processingPurpose", "dataCategories"],
    },
  },
  {
    name: "run_adversarial_tests",
    description:
      "Executes adversarial robustness testing: prompt injection, jailbreak attempts, OOD detection. " +
      "🔗 EU AI Act Art. 15 | NIST AI RMF MEASURE 1.3 | ISO/IEC 42001 Clause 8.1.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        testSuites: {
          type: "array",
          items: {
            type: "string",
            enum: ["prompt_injection", "jailbreak", "ood_detection", "model_inversion", "membership_inference"],
          },
          description: "Selected adversarial test suites to execute",
        },
        severityThreshold: {
          type: "string",
          enum: ["low", "medium", "high"],
          default: "medium",
          description: "Minimum severity to flag as failure",
        },
      },
      required: ["modelId", "testSuites"],
    },
  },
  {
    name: "score_audit_weighted",
    description:
      "Aggregates all previous audit phases into a weighted score (0–100). " +
      "**Halts certification** immediately if any BLOCKER FAIL is detected. " +
      "🔗 NIST AI RMF MEASURE 4.1 | ISO/IEC 42001 Clause 9.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        riskTier: {
          type: "object",
          properties: {
            tier: { type: "string" },
            compliant: { type: "boolean" },
          },
          description: "Risk classification result from classify_ai_risk",
        },
        supplyChain: {
          type: "object",
          properties: {
            ipClearance: { type: "boolean" },
            compliant: { type: "boolean" },
          },
          description: "Supply chain audit result from audit_supply_chain",
        },
        oversight: {
          type": "object",
          properties: {
            blocker: { type: "boolean" },
            compliant: { type: "boolean" },
          },
          description: "Human oversight result from verify_human_oversight",
        },
        bias: {
          type: "object",
          properties: {
            overallBiasRisk: { type": "string" },
            compliant: { type: "boolean" },
          },
          description: "Bias assessment result from run_bias_assessment",
        },
        dpia: {
          type: "object",
          properties: {
            compliant: { type: "boolean" },
          },
          description: "DPIA report result from generate_dpia",
        },
        adversarial: {
          type: "object",
          properties: {
            overallRisk: { type: "string" },
            compliant: { type": "boolean" },
          },
          description: "Adversarial test result from run_adversarial_tests",
        },
      },
      required: ["modelId"],
    },
  },
  {
    name: "generate_audit_certificate",
    description:
      "Issues a cryptographically signed W3C Verifiable Credential (VC-JSON) " +
      "for the completed audit. Saves to PostgreSQL evidence store. " +
      "🔗 W3C VC Data Model 1.1 | ISO/IEC 42001 Clause 7.5 (Documented Information)",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        weightedScore: { type: "number", description: "Final weighted audit score (0–100)" },
        tier: {
          type: "string",
          enum: ["prohibited", "high", "limited", "minimal", "certified"],
          description: "Final risk tier or certification level",
        },
        compliant: { type": "boolean", description: "Overall compliance status" },
        issuerName: { type: "string", description: "Name of the issuing authority" },
        validDays: {
          type: "number",
          description: "Validity period in days (default: 365)",
          default: 365,
        },
      },
      required: ["modelId", "weightedScore", "tier", "compliant", "issuerName"],
    },
  },
  {
    name: "monitor_model_drift",
    description:
      "Sets up continuous post-deployment drift monitoring using Evidently AI. " +
      "Triggers re-audit workflows if drift exceeds thresholds. " +
      "🔗 EU AI Act Art. 15 | NIST AI RMF MEASURE 3.3 | ISO/IEC 42001 Clause 9.1 (Monitoring)",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type": "string", description: "Unique model identifier" },
        referenceData: {
          type: "array",
          items: { type: "object" },
          description: "Reference/baseline dataset for drift comparison",
        },
        productionData: {
          type: "array",
          items: { type: "object" },
          description: "Current production data for drift evaluation",
        },
        driftThreshold: {
          type: "number",
          description: "PSI/KS threshold for drift alert (default: 0.1)",
          default: 0.1,
        },
        features: {
          type: "array",
          items: { type: "string" },
          description: "List of feature names to monitor for drift",
        },
      },
      required: ["modelId", "referenceData", "productionData", "features"],
    },
  },
  {
    name: "audit_session_memory",
    description:
      "Audits short-term and long-term memory isolation for AI agents. " +
      "Verifies session data wipe-on-expiry, context window limits, " +
      "and cross-session data leakage prevention. " +
      "GDPR Art. 5(1)(f) | GDPR Art. 25 | DPDP Act Sec. 8 | EU AI Act Art. 15",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        sessionId: { type: "string", description: "Session identifier to audit" },
        stmConfig: {
          type: "object",
          description: "Short-term memory configuration (maxTokens, maxHistory, wipeOnExpiry, isolation, etc.)",
        },
        ltmConfig: {
          type: "object",
          description: "Long-term memory configuration (optional)",
        },
        sessionTimeoutMinutes: {
          type: "number",
          description: "Session timeout in minutes (default: 30)",
          default: 30,
        },
        isolationLevel: {
          type: "string",
          enum: ["per_user", "per_session", "shared"],
          description: "Memory isolation level",
          default: "per_user",
        },
      },
      required: ["modelId", "sessionId", "stmConfig"],
    },
  },
  {
    name: "audit_rag_quality",
    description:
      "Evaluates RAG pipeline quality: retrieval accuracy, embedding bias, " +
      "knowledge freshness, hallucination rate. Tests against sample queries " +
      "with expected answers. " +
      "EU AI Act Art. 15 | NIST AI RMF MEASURE 3.3 | ISO/IEC 42001 Clause 9.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        vectorDbConfig: {
          type: "object",
          description: "Vector DB configuration (totalSources, freshSources, protectedGroups, biasScores)",
        },
        sampleQueries: {
          type: "array",
          items: { type: "object" },
          description: "Sample queries with expected answers and relevance scores",
        },
        freshnessPolicyDays: {
          type: "number",
          description: "Knowledge freshness policy in days (default: 90)",
          default: 90,
        },
      },
      required: ["modelId", "vectorDbConfig", "sampleQueries"],
    },
  },
  {
    name: "audit_prompt_templates",
    description:
      "Audits prompt engineering templates for injection surface, few-shot bias, " +
      "instruction safety, and transparency compliance. " +
      "EU AI Act Art. 10, 13 | NIST AI RMF GOVERN 1.2 | ISO/IEC 42001 Clause 8.1.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        promptTemplates: {
          type: "array",
          items: { type: "object" },
          description: "Array of prompt templates to audit [{name, template, role, use_case}]",
        },
        fewShotExamples: {
          type": "array",
          items: { type: "object" },
          description: "Few-shot examples to check for bias (optional)",
        },
        systemPrompt: {
          type: "string",
          description: "System prompt to audit (optional)",
        },
      },
      required: ["modelId", "promptTemplates"],
    },
  },
  {
    name: "audit_agent_trust",
    description:
      "Audits multi-agent trust: identity verification, capability claims validation, " +
      "P2P message integrity, collusion detection, and cross-agent data leakage risk. " +
      "EU AI Act Art. 12, 14 | NIST GOVERN 1.2 | DPDP Act Sec. 8 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        agents: {
          type: "array",
          items: { type: "object" },
          description: "Array of agent configs [{agentId, role, capabilities, tools, hasIdentity, hasSignature}]",
        },
        messageBusConfig: {
          type: "object",
n          description: "Message bus configuration (hmac, signing, authentication)",
        },
        p2pEnabled: {
          type: "boolean",
          description: "Whether peer-to-peer agent communication is enabled",
          default: false,
        },
      },
      required: ["modelId", "agents"],
    },
  },
  {
    name: "audit_tool_permissions",
    description:
      "Audits tool permission boundaries: verifies agents only access authorized tools, " +
      "detects privilege escalation, unauthorized access, and permission drift. " +
      "DPDP Act Sec. 8 | EU AI Act Art. 14 | GDPR Art. 25 | ISO/IEC 42001 Clause 7.4.3",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type type: "string", description: "Unique model identifier" },
        toolRegistry: {
          type: "array",
          items: { type: "object" },
          description: "Tool registry [{toolName, permissions, agents, scopes, lastAuditedPermissions}]",
        },
        accessLogs: {
          type: "array",
          items: { type: "object" },
          description: "Access logs [{timestamp, agentId, toolName, action, result, scope}]",
        },
      },
      required: ["modelId", "toolRegistry", "accessLogs"],
    },
  },
  {
    name: "classify_agent_autonomy",
    description:
      "Classifies AI agent autonomy level (assistive/supervised/autonomous/fully_autonomous) " +
      "and maps to EU AI Act risk tiers. Determines required human oversight controls. " +
      "EU AI Act Art. 6, 14 | NIST AI RMF GOVERN 3.2 | ISO/IEC 42001 Clause 6.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: { type: "string", description: "Unique model identifier" },
        agentType: {
          type: "string",
          enum: ["single", "multi_agent", "hierarchical", "swarm"],
          description: "Type of agent architecture",
        },
        hasHumanOversight: { type: "boolean", description: "Does the agent have human oversight?" },
        canMakeDecisions: { type: "boolean", description: "Can the agent make autonomous decisions?" },
        canModifyEnvironment: { type: "boolean", description: "Can the agent modify its environment?" },
        canDelegateTasks: { type: "boolean", description: "Can the agent delegate tasks to other agents?" },
        canAccessExternalAPIs: { type: "boolean", description: "Can the agent access external APIs?" },
        canSelfModify: { type: "boolean", description: "Can the agent modify its own prompts/weights?" },
        deploymentContext: {
          type: "string",
          enum: ["real_time", "batch", "assistive", "autonomous"],
          description: "Deployment context",
          default: "assistive",
        },
      },
      required: ["modelId", "agentType", "hasHumanOversight", "canMakeDecisions"],
    },
  },
];

// ─── Handler: List Available Tools ───────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map(({ name, description, inputSchema }) => ({
    name,
    description,
    inputSchema: inputSchema as Record<string, unknown>,
  })),
}));

// ─── Handler: Call Tool ──────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (!args) {
    return {
      content: [{ type: "text", text: "Error: No arguments provided." }],
      isError: true,
    };
  }

  try {
    switch (name) {
      // ── Tool 0: assess_dpdp_compliance ─────────────────────────
      case "assess_dpdp_compliance": {
        const result = await callPythonBackend<DPDPComplianceReport>("/api/dpdp/assess", {
          body: args,
        });
        return formatSuccess(result, "India DPDP Act 2023 Compliance Report");
      }

      // ── Tool 1: discover_supply_chain ──────────────────────────
      case "discover_supply_chain": {
        const result = await callPythonBackend("/api/supply-chain/discover", {
          body: args,
          timeout: 120000,  // Discovery may take longer
        });
        return formatSuccess(result, "Supply Chain Discovery");
      }

      // ── Tool 2: classify_ai_risk ───────────────────────────────
      case "classify_ai_risk": {
        const result = await callPythonBackend<RiskTierResult>("/api/risk/classify", {
          body: args,
        });
        return formatSuccess(result, "Risk Classification");
      }

      // ── Tool 3: audit_supply_chain ─────────────────────────────
      case "audit_supply_chain": {
        const result = await callPythonBackend<ProvenanceReport>("/api/supply-chain/audit", {
          body: args,
        });
        return formatSuccess(result, "Supply Chain Audit");
      }

      // ── Tool 4: verify_human_oversight ─────────────────────────
      case "verify_human_oversight": {
        const result = await callPythonBackend<OversightCertificate>(
          "/api/human-oversight/verify",
          { body: args },
        );
        // BLOCKER FAIL — immediately return a strict failure if blocker is true
        if (result.blocker) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(result, null, 2),
              },
              {
                type: "text",
                text: "❌ BLOCKER FAIL: Human oversight mechanisms are insufficient. " +
                  "Certification cannot proceed. "
                  + "EU AI Act Art. 14 requires HITL/HOTL controls. "
                  + `Remediation: ${result.remediation || "Implement kill-switch and human review process."}`
              },
            ],
            isError: true,
          };
        }
        return formatSuccess(result, "Human Oversight Verification");
      }

      // ── Tool 5: run_bias_assessment ────────────────────────────
      case "run_bias_assessment": {
        const result = await callPythonBackend<BiasReport>("/api/bias/assess", {
          body: args,
        });
        return formatSuccess(result, "Bias Assessment");
      }

      // ── Tool 6: generate_dpia ──────────────────────────────────
      case "generate_dpia": {
        const result = await callPythonBackend<DPIAReport>("/api/dpia/generate", {
          body: args,
        });
        return formatSuccess(result, "DPIA Report");
      }

      // ── Tool 7: run_adversarial_tests ──────────────────────────
      case "run_adversarial_tests": {
        const result = await callPythonBackend<AdversarialReport>(
          "/api/adversarial/run",
          { body: args },
        );
        return formatStatus(result, "Adversarial Test Report");
      }

      // ── Tool 8: score_audit_weighted ───────────────────────────
      case "score_audit_weighted": {
        const result = await callPythonBackend<WeightedAuditScore>(
          "/api/scoring/weighted",
          { body: args },
        );
        // Halt certification if blocker failures exist
        if (result.blockerFailures.length > 0) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(result, null, 2),
              },
              {
                type: "text",
                text: `🛑 CERTIFICATION HALTED: ${result.blockerFailures.length} blocker failure(s) detected.\n"
                  + "Blocker(s): ${result.blockerFailures.join(", ")}\n"
                  + "Resolution required before certification can proceed.",
              },
            ],
            isError: true,
          };
        }
        return formatSuccess(result, "Weighted Audit Score");
      }

      // ── Tool 9: generate_audit_certificate ─────────────────────
      case "generate_audit_certificate": {
        const result = await callPythonBackend<AuditCertificate>(
          "/api/certificate/generate",
          { body: args, timeout: 120000 },
        );
        return formatSuccess(result, "Audit Certificate (W3C VC-JSON)");
      }

      // ── Tool 10: monitor_model_drift ────────────────────────────
      case "monitor_model_drift": {
        const result = await callPythonBackend<DriftReport>("/api/drift/monitor", {
          body: args,
        });
        return formatSuccess(result, "Model Drift Report");
      }

      // ── Tool 11: audit_session_memory ─────────────────────────
      case "audit_session_memory": {
        const result = await callPythonBackend<SessionMemoryReport>(
          "/api/session-memory/audit",
          { body: args },
        );
        return formatSuccess(result, "Session Memory Audit");
      }

      // ── Tool 12: audit_rag_quality ────────────────────────────
      case "audit_rag_quality": {
        const result = await callPythonBackend<RAGQualityReport>(
          "/api/rag-quality/evaluate",
          { body: args },
        );
        return formatSuccess(result, "RAG Quality Report");
      }

      // ── Tool 13: audit_prompt_templates ────────────────────────
      case "audit_prompt_templates": {
        const result = await callPythonBackend<PromptAuditReport>(
          "/api/prompt-audit/evaluate",
          { body: args },
        );
        return formatSuccess(result, "Prompt Template Audit");
      }

      // ── Tool 14: audit_agent_trust ────────────────────────────
      case "audit_agent_trust": {
        const result = await callPythonBackend<AgentTrustReport>(
          "/api/agent-trust/evaluate",
          { body: args },
        );
        return formatSuccess(result, "Agent Trust Audit");
      }

      // ── Tool 15: audit_tool_permissions ────────────────────────
      case "audit_tool_permissions": {
        const result = await callPythonBackend<ToolPermissionReport>(
          "/api/tool-permissions/evaluate",
          { body: args },
        );
        return formatSuccess(result, "Tool Permission Audit");
      }

      // ── Tool 16: classify_agent_autonomy ──────────────────────
      case "classify_agent_autonomy": {
        const result = await callPythonBackend<AgentAutonomyResult>(
          "/api/agent-autonomy/classify",
          { body: args },
        );
        // BLOCKER FAIL for fully autonomous agents
        if (result.autonomyLevel === "fully_autonomous") {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(result, null, 2),
              },
              {
                type: "text",
                text: "BLOCKER FAIL: Fully autonomous agent detected. " +
                  "EU AI Act Art. 14 requires human oversight for high-risk AI. " +
                  "Autonomous operation without oversight is BLOCKED. " +
                  "Implement human-in-the-loop controls before deployment.",
              },
            ],
            isError: true,
          };
        }
        return formatSuccess(result, "Agent Autonomy Classification");
      }

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: `Error executing ${name}: ${message}`,
        },
      ],
      isError: true,
    };
  }
});

// ─── Start MCP Server ────────────────────────────────────────────
// Supports both stdio (Claude Desktop) and SSE (web/API) transports.

async function main() {
  const transportType = process.env.MCP_TRANSPORT || "stdio";

  if (transportType === "sse") {
    // SSE Transport: used for web-based MCP clients
    const express = (await import("express")).default;
    const app = express();
    app.use(express.json());
    const transports: Map<string, SSEServerTransport> = new Map();

    // Health check for Docker orchestration
    app.get("/health", (_req, res) => {
      res.json({
        status: "ok",
        transport: "sse",
        sessionCount: transports.size,
        version: "1.0.0",
      });
    });

    app.get("/sse", async (req, res) => {
      const transport = new SSEServerTransport("/messages", res);
      const sessionId = transport.sessionId;
      transports.set(sessionId, transport);
      res.on("close", () => transports.delete(sessionId));
      await server.connect(transport);
    });

    app.post("/messages", async (req, res) => {
      const sessionId = req.query.sessionId as string;
      const transport = transports.get(sessionId);
      if (transport) {
        await transport.handlePostMessage(req, res);
      } else {
        res.status(404).json({ error: "Session not found" });
      }
    });

    const port = parseInt(process.env.PORT || "3000", 10);
    app.listen(port, () => {
      console.error(`[ComplianceStack MCP] SSE transport listening on port ${port}`);
    });
  } else {
    // Stdio Transport: used for Claude Desktop and direct CLI integration
    const transport = new StdioServerTransport();
    console.error("[ComplianceStack MCP] Starting with stdio transport...");
    await server.connect(transport);
  }
}

main().catch((error) => {
  console.error("[ComplianceStack MCP] Fatal error:", error);
  process.exit(1);
});
