#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nyayosh Bharuchanb15-Max
// ═══════════════════════════════════════════════════════════════════
//  ComplianceStack MCP Server — Complete Implementation v3.1.0
//  Exposes 17 audit tools, 5 resources, and 4 prompts via the
//  Model Context Protocol SDK with all three transport modes.
//  Connected to Python FastAPI Backend for all audit logic.
//  ================================================================

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  CancelledNotificationSchema,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import { callPythonBackend } from "./client.js";
import { validateToolInput } from "./validator.js";
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
import { TOOL_SCHEMAS } from "./tool-schemas.js";
import {
  GOVERNANCE_TOOL_SCHEMAS,
  isGovernanceTool,
  handleGovernanceTool,
} from "./governance-tools.js";
import { ERROR_CODE_REQUEST_CANCELLED } from "./errors.js";

// ─── Constants ────────────────────────────────────────────────────
const SERVER_VERSION = "3.1.0";
const SERVER_NAME = "compliance-stack-mcp-server";

// ─── Structured MCP Error Helper ──────────────────────────────────

function mcpError(code: ErrorCode, message: string, data?: unknown): {
  content: Array<{ type: "text"; text: string }>;
  isError: true;
} {
  return {
    content: [{ type: "text", text: message }],
    isError: true as const,
  };
}

// ─── Progress Notification Helper ─────────────────────────────────

type SendNotificationFn = (notification: { method: string; params?: Record<string, unknown> }) => Promise<void>;

async function sendProgress(
  sendNotification: SendNotificationFn,
  progressToken: string | number | undefined,
  progress: number,
  total: number,
  message?: string,
): Promise<void> {
  if (progressToken !== undefined) {
    await sendNotification({
      method: "notifications/progress",
      params: {
        progressToken,
        progress,
        total,
        ...(message ? { message } : {}),
      },
    });
  }
}

// ─── Response Formatters ──────────────────────────────────────────

function formatSuccess(result: unknown, label: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: `📋 ${label} Result:\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``,
      },
    ],
  };
}

function formatResource(uri: string, mimeType: string, text: string) {
  return {
    contents: [
      {
        uri,
        mimeType,
        text,
      },
    ],
  };
}

// ─── Cancellation Tracking ────────────────────────────────────────

const cancelledRequests = new Set<string | number>();

function isCancelled(requestId: string | number): boolean {
  return cancelledRequests.has(requestId);
}

// ─── MCP Server Instance ──────────────────────────────────────────

const server = new Server(
  {
    name: SERVER_NAME,
    version: SERVER_VERSION,
  },
  {
    capabilities: {
      tools: {
        listChanged: true,
      },
      resources: {
        listChanged: true,
      },
      prompts: {
        listChanged: true,
      },
      logging: {},
    },
  },
);

// ═══════════════════════════════════════════════════════════════════
//  TOOL DEFINITIONS — Rigorous JSON Schema with full validation
// ═══════════════════════════════════════════════════════════════════

const TOOLS = [...TOOL_SCHEMAS, ...GOVERNANCE_TOOL_SCHEMAS].map((t) => ({
  name: t.name,
  description: t.description,
  inputSchema: t.inputSchema,
}));

// ═══════════════════════════════════════════════════════════════════
//  MCP RESOURCES — Regulatory framework references
// ═══════════════════════════════════════════════════════════════════

const RESOURCES = [
  {
    uri: "compliance://frameworks/eu-ai-act",
    name: "EU AI Act (Regulation 2024/1689)",
    description: "European Union Artificial Intelligence Act risk classification framework. Covers prohibited AI practices (Art. 5), high-risk classification (Art. 6, Annex III), transparency obligations (Art. 50), and conformity assessment procedures.",
    mimeType: "application/json",
  },
  {
    uri: "compliance://frameworks/gdpr",
    name: "GDPR (Regulation 2016/679)",
    description: "General Data Protection Regulation compliance framework. Covers data protection principles (Art. 5), lawfulness of processing (Art. 6), DPIA requirements (Art. 35), ROPA (Art. 30), and cross-border transfer mechanisms (Art. 44–49).",
    mimeType: "application/json",
  },
  {
    uri: "compliance://frameworks/nist-ai-rmf",
    name: "NIST AI RMF (AI 100-1)",
    description: "NIST AI Risk Management Framework. Covers MAP 1.1 (risk identification), GOVERN 1.2/3.2 (governance), MEASURE 1.3/2.2/3.3/4.1 (measurement and monitoring).",
    mimeType: "application/json",
  },
  {
    uri: "compliance://frameworks/iso-42001",
    name: "ISO/IEC 42001:2023",
    description: "AI Management System standard. Covers Clause 6.1 (risk assessment), 6.2 (objectives), 7.4.3 (supply chain), 7.5 (documented information), 8.1.2/8.1.3 (operational planning), 8.2 (risk assessment), 9.1 (monitoring).",
    mimeType: "application/json",
  },
  {
    uri: "compliance://frameworks/dpdp-act",
    name: "India DPDP Act 2023",
    description: "Digital Personal Data Protection Act. Covers Sec. 5 (notice), Sec. 6 (consent), Sec. 7 (legitimate uses), Sec. 8 (fiduciary obligations), Sec. 9 (children's data), Sec. 10 (Significant Data Fiduciary/DPO), Sec. 11–12 (data principal rights — access, correction, erasure), Sec. 13 (grievance redressal), Sec. 16 (cross-border transfers).",
    mimeType: "application/json",
  },
];

// ═══════════════════════════════════════════════════════════════════
//  MCP PROMPTS — Guided compliance workflows
// ═══════════════════════════════════════════════════════════════════

const PROMPTS = [
  {
    name: "full-model-audit",
    description: "Run a complete 17-phase compliance audit on an AI model across all five regulatory frameworks",
    arguments: [
      { name: "modelId", description: "Unique model identifier to audit", required: true },
      { name: "modelType", description: "EU AI Act model category (e.g. 'employment', 'credit', 'law_enforcement')", required: true },
      { name: "sector", description: "Deployment sector (e.g. 'healthcare', 'finance')", required: true },
      { name: "dataController", description: "Data controller name for GDPR DPIA", required: true },
      { name: "dpoName", description: "Data Protection Officer name", required: true },
    ],
  },
  {
    name: "dpdp-quick-check",
    description: "Quick India DPDP Act 2023 compliance assessment for a model and its data fiduciary",
    arguments: [
      { name: "modelId", description: "Model identifier to assess", required: true },
      { name: "dataFiduciary", description: "Name of the Data Fiduciary under DPDP Act", required: true },
    ],
  },
  {
    name: "agent-trust-audit",
    description: "Audit multi-agent system trust boundaries, tool permissions, and autonomy classification",
    arguments: [
      { name: "modelId", description: "Model/agent system identifier", required: true },
      { name: "agentCount", description: "Number of agents in the system", required: true },
      { name: "hasHumanOversight", description: "Whether human oversight is in place", required: true },
    ],
  },
  {
    name: "risk-classify-only",
    description: "Classify a model's EU AI Act risk tier without running the full audit pipeline",
    arguments: [
      { name: "modelId", description: "Model identifier", required: true },
      { name: "modelType", description: "EU AI Act model category", required: true },
      { name: "sector", description: "Deployment sector", required: true },
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════
//  HANDLER: List Available Tools
// ═══════════════════════════════════════════════════════════════════

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map(({ name, description, inputSchema }) => ({
    name,
    description,
    inputSchema: inputSchema as Record<string, unknown>,
  })),
}));

// ═══════════════════════════════════════════════════════════════════
//  HANDLER: List Available Resources
// ═══════════════════════════════════════════════════════════════════

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: RESOURCES.map(({ uri, name, description, mimeType }) => ({
    uri,
    name,
    description,
    mimeType,
  })),
}));

// ═══════════════════════════════════════════════════════════════════
//  HANDLER: Read Resource Content
// ═══════════════════════════════════════════════════════════════════

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  const resourceData: Record<string, object> = {
    "compliance://frameworks/eu-ai-act": {
      framework: "EU AI Act (Regulation 2024/1689)",
      status: "In force since August 1, 2024",
      riskTiers: ["Unacceptable Risk (Art. 5)", "High Risk (Art. 6, Annex III)", "Limited Risk (Art. 50)", "Minimal Risk"],
      keyArticles: {
        "Art. 5": "Prohibited AI practices (social scoring, real-time biometric surveillance)",
        "Art. 6": "High-risk AI system classification criteria",
        "Art. 10": "Data governance requirements for training data",
        "Art. 11": "Technical documentation for high-risk AI systems",
        "Art. 12": "Record-keeping (automatic logging of events)",
        "Art. 14": "Human oversight requirements for high-risk systems",
        "Art. 15": "Accuracy, robustness, and cybersecurity requirements",
        "Art. 50": "Transparency obligations for limited-risk systems",
        "Annex III": "High-risk use cases (employment, credit, law enforcement, etc.)",
      },
      complianceTools: ["classify_ai_risk", "discover_supply_chain", "audit_supply_chain", "verify_human_oversight", "run_bias_assessment", "run_adversarial_tests"],
    },
    "compliance://frameworks/gdpr": {
      framework: "GDPR (Regulation 2016/679)",
      status: "In force since May 25, 2018",
      keyArticles: {
        "Art. 5": "Principles of processing (lawfulness, fairness, transparency, purpose limitation, data minimisation, accuracy, storage limitation, integrity/confidentiality, accountability)",
        "Art. 9": "Processing of special categories of personal data",
        "Art. 22": "Automated individual decision-making, including profiling",
        "Art. 25": "Data protection by design and by default",
        "Art. 30": "Records of processing activities (ROPA)",
        "Art. 35": "Data Protection Impact Assessment (DPIA)",
        "Art. 44–49": "Transfers of personal data to third countries",
      },
      complianceTools: ["generate_dpia", "run_bias_assessment", "audit_session_memory", "generate_audit_certificate"],
    },
    "compliance://frameworks/nist-ai-rmf": {
      framework: "NIST AI Risk Management Framework (AI 100-1)",
      status: "Published January 2023",
      functions: {
        "GOVERN": "Establish and maintain AI risk management culture (GOVERN 1.2, 3.2)",
        "MAP": "Context and risk identification (MAP 1.1)",
        "MEASURE": "Analyze, assess, and quantify AI risk (MEASURE 1.3, 2.2, 3.3, 4.1)",
        "MANAGE": "Allocate resources and manage risk based on assessment",
      },
      complianceTools: ["classify_ai_risk", "audit_supply_chain", "run_bias_assessment", "monitor_model_drift", "score_audit_weighted"],
    },
    "compliance://frameworks/iso-42001": {
      framework: "ISO/IEC 42001:2023 — AI Management System",
      status: "Published December 2023",
      keyClauses: {
        "6.1": "Actions to address risks and opportunities",
        "6.2": "AI management system objectives and planning",
        "7.4.3": "Information, documentation, and supply chain",
        "7.5": "Documented information (evidence retention requirements)",
        "8.1.2": "AI system impact assessment",
        "8.1.3": "AI system development and operations",
        "8.2": "Risk assessment",
        "9.1": "Monitoring, measurement, analysis, and evaluation",
      },
      complianceTools: ["generate_audit_certificate", "score_audit_weighted", "monitor_model_drift"],
    },
    "compliance://frameworks/dpdp-act": {
      framework: "India Digital Personal Data Protection Act 2023",
      status: "Enacted August 11, 2023; Rules notified November 13, 2025 (G.S.R. 846(E))",
      keySections: {
        "Sec. 5": "Notice requirements before consent request",
        "Sec. 6": "Consent (free, specific, informed, unconditional, unambiguous)",
        "Sec. 7": "Legitimate uses (including deemed consent scenarios)",
        "Sec. 8": "General obligations of Data Fiduciary (security, breach notification, retention)",
        "Sec. 9": "Processing of children's data (verifiable parental consent)",
        "Sec. 10": "Significant Data Fiduciary (DPO appointment, audits, DPIA)",
        "Sec. 11": "Right to access information about personal data",
        "Sec. 12": "Right to correction and erasure",
        "Sec. 13": "Right to grievance redressal",
        "Sec. 14": "Right to nominate",
        "Sec. 16": "Cross-border transfer of personal data",
      },
      complianceTools: ["assess_dpdp_compliance"],
    },
  };

  const data = resourceData[uri];
  if (!data) {
    return mcpError(ErrorCode.InvalidRequest, `Unknown resource URI: ${uri}`);
  }

  return formatResource(uri, "application/json", JSON.stringify(data, null, 2));
});

// ═══════════════════════════════════════════════════════════════════
//  HANDLER: List Available Prompts
// ═══════════════════════════════════════════════════════════════════

server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: PROMPTS.map(({ name, description, arguments: args }) => ({
    name,
    description,
    arguments: args,
  })),
}));

// ═══════════════════════════════════════════════════════════════════
//  HANDLER: Get Prompt Content
// ═══════════════════════════════════════════════════════════════════

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "full-model-audit": {
      const modelId = args?.modelId || "unknown-model";
      const modelType = args?.modelType || "general_purpose_ai";
      const sector = args?.sector || "other";
      const dataController = args?.dataController || "Unknown Controller";
      const dpoName = args?.dpoName || "Unknown DPO";

      return {
        description: `Complete 17-phase compliance audit for model "${modelId}"`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text:
                `I need to run a full compliance audit on model "${modelId}". ` +
                `Please execute the following steps in order:\n\n` +
                `1. classify_ai_risk — Model type: ${modelType}, Sector: ${sector}\n` +
                `2. discover_supply_chain — Auto-discover model artifacts\n` +
                `3. audit_supply_chain — Verify data lineage and IP clearance\n` +
                `4. verify_human_oversight — Check HITL and kill-switch controls\n` +
                `5. run_bias_assessment — Test protected attributes for fairness\n` +
                `6. generate_dpia — DPIA for ${dataController}, DPO: ${dpoName}\n` +
                `7. run_adversarial_tests — Test prompt injection, jailbreak, OOD\n` +
                `8. score_audit_weighted — Aggregate all phases\n` +
                `9. generate_audit_certificate — Issue W3C VC if compliant\n\n` +
                `For each phase, use the corresponding ComplianceStack MCP tool. ` +
                `Report BLOCKER FAILs immediately. Provide regulatory article references for all findings.`,
            },
          },
        ],
      };
    }

    case "dpdp-quick-check": {
      const modelId = args?.modelId || "unknown-model";
      const dataFiduciary = args?.dataFiduciary || "Unknown Fiduciary";

      return {
        description: `Quick DPDP Act compliance check for model "${modelId}"`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text:
                `Assess the India DPDP Act 2023 compliance for model "${modelId}". ` +
                `Data Fiduciary: ${dataFiduciary}. ` +
                `Use the assess_dpdp_compliance tool and evaluate: ` +
                `consent mechanisms (Sec. 5/6), fiduciary duties (Sec. 8), ` +
                `data principal rights (Sec. 11–14). ` +
                `Provide section-by-section findings with remediation steps.`,
            },
          },
        ],
      };
    }

    case "agent-trust-audit": {
      const modelId = args?.modelId || "unknown-model";
      const agentCount = args?.agentCount || "2";
      const hasHumanOversight = args?.hasHumanOversight || "false";

      return {
        description: `Multi-agent trust audit for system "${modelId}"`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text:
                `Audit the multi-agent trust system "${modelId}" with ${agentCount} agents. ` +
                `Human oversight: ${hasHumanOversight}. ` +
                `Execute these tools in sequence:\n` +
                `1. audit_agent_trust — Verify agent identities and message integrity\n` +
                `2. audit_tool_permissions — Check permission boundaries and privilege escalation\n` +
                `3. classify_agent_autonomy — Determine autonomy level and required controls\n\n` +
                `Report any BLOCKER FAILs (e.g., fully autonomous without oversight). ` +
                `Map findings to EU AI Act Art. 12/14 and ISO/IEC 42001 Clause 7.4.3.`,
            },
          },
        ],
      };
    }

    case "risk-classify-only": {
      const modelId = args?.modelId || "unknown-model";
      const modelType = args?.modelType || "general_purpose_ai";
      const sector = args?.sector || "other";

      return {
        description: `Quick EU AI Act risk classification for model "${modelId}"`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text:
                `Classify model "${modelId}" under the EU AI Act risk framework. ` +
                `Model type: ${modelType}. Sector: ${sector}. ` +
                `Use the classify_ai_risk tool and provide the risk tier with rationale ` +
                `and regulatory article references (Art. 6, Annex I–III).`,
            },
          },
        ],
      };
    }

    default:
      return mcpError(ErrorCode.InvalidRequest, `Unknown prompt: ${name}`);
  }
});

// ═══════════════════════════════════════════════════════════════════
//  HANDLER: Cancelled Notification (MCP spec §notifications/cancelled)
// ═══════════════════════════════════════════════════════════════════

server.setNotificationHandler(CancelledNotificationSchema, async (notification) => {
  const { requestId, reason } = notification.params;
  if (requestId === undefined) return;
  cancelledRequests.add(requestId);
  console.error(
    `[ComplianceStack MCP] Request ${requestId} cancelled: ${reason || "no reason provided"}`
  );
});

// ═══════════════════════════════════════════════════════════════════
//  HANDLER: Call Tool (with progress tokens, cancellation, errors)
// ═══════════════════════════════════════════════════════════════════

server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  const { name, arguments: args } = request.params;
  const requestId = extra.requestId;
  const _meta = (request.params as Record<string, unknown>)._meta as
    | { progressToken?: string | number }
    | undefined;
  const progressToken = _meta?.progressToken;

  // Check if request was cancelled
  if (isCancelled(requestId)) {
    cancelledRequests.delete(requestId);
    return mcpError(ERROR_CODE_REQUEST_CANCELLED as unknown as ErrorCode, "Request was cancelled by the client");
  }

  // Governance pipeline tools (9-phase flow) — validated + authorized at the
  // MCP layer inside handleGovernanceTool before FastAPI is invoked.
  if (isGovernanceTool(name)) {
    return await handleGovernanceTool(name, (args ?? {}) as Record<string, unknown>);
  }

   if (!args) {
     return mcpError(ErrorCode.InvalidParams, "No arguments provided");
   }

   // Validate modelId is present and non-empty for all tools
   if (typeof args.modelId !== "string" || args.modelId.trim().length === 0) {
     return mcpError(ErrorCode.InvalidParams, "modelId is required");
   }

   // Validate modelId format
   if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(args.modelId as string)) {
     return mcpError(
       ErrorCode.InvalidParams,
       "The 'modelId' must start with an alphanumeric character and contain only letters, numbers, dots, hyphens, or underscores.",
     );
   }

  // MCP-layer input validation against JSON Schema
  const validation = validateToolInput(name, args as Record<string, unknown>);
  if (!validation.valid) {
    const errorMessages = validation.errors?.map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ");
    return mcpError(
      ErrorCode.InvalidParams,
      `Input validation failed for tool '${name}': ${errorMessages}`,
    );
  }

  try {
    // Send initial progress
    await sendProgress(
      extra?.sendNotification?.bind(extra) || (async () => {}),
      progressToken,
      0,
      100,
      `Starting ${name}...`,
    );

    switch (name) {
      // ── Tool 1: classify_ai_risk ───────────────────────────────
      case "classify_ai_risk": {
        const result = await callPythonBackend<RiskTierResult>("/api/risk/classify", {
          body: args,
        });
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Risk classification complete",
        );
        return formatSuccess(result, "Risk Classification");
      }

      // ── Tool 2: discover_supply_chain ──────────────────────────
      case "discover_supply_chain": {
        const result = await callPythonBackend<DiscoveryResult>("/api/supply-chain/discover", {
          body: args,
          timeout: 120000,
        });
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Supply chain discovery complete",
        );
        return formatSuccess(result, "Supply Chain Discovery");
      }

      // ── Tool 3: audit_supply_chain ─────────────────────────────
      case "audit_supply_chain": {
        const result = await callPythonBackend<ProvenanceReport>("/api/supply-chain/audit", {
          body: args,
        });
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Supply chain audit complete",
        );
        return formatSuccess(result, "Supply Chain Audit");
      }

      // ── Tool 4: verify_human_oversight ─────────────────────────
      case "verify_human_oversight": {
        const result = await callPythonBackend<OversightCertificate>(
          "/api/human-oversight/verify",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Human oversight verification complete",
        );
        if (result.blocker) {
          return {
            content: [
              {
                type: "text" as const,
                text: `📋 Human Oversight Verification Result:\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``,
              },
              {
                type: "text" as const,
                text:
                  "❌ BLOCKER FAIL: Human oversight mechanisms are insufficient. " +
                  "Certification cannot proceed. " +
                  "EU AI Act Art. 14 requires HITL/HOTL controls for high-risk AI systems. " +
                  `Remediation: ${result.remediation || "Implement kill-switch and human review process."}`,
              },
            ],
            isError: true as const,
          };
        }
        return formatSuccess(result, "Human Oversight Verification");
      }

      // ── Tool 5: run_bias_assessment ────────────────────────────
      case "run_bias_assessment": {
        const result = await callPythonBackend<BiasReport>("/api/bias/assess", {
          body: args,
        });
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Bias assessment complete",
        );
        return formatSuccess(result, "Bias Assessment");
      }

      // ── Tool 6: generate_dpia ──────────────────────────────────
      case "generate_dpia": {
        const result = await callPythonBackend<DPIAReport>("/api/dpia/generate", {
          body: args,
        });
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "DPIA generation complete",
        );
        return formatSuccess(result, "DPIA Report");
      }

      // ── Tool 7: run_adversarial_tests ──────────────────────────
      case "run_adversarial_tests": {
        const result = await callPythonBackend<AdversarialReport>(
          "/api/adversarial/run",
          { body: args, timeout: 180000 },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Adversarial testing complete",
        );
        return formatSuccess(result, "Adversarial Test Report");
      }

      // ── Tool 8: score_audit_weighted ───────────────────────────
      case "score_audit_weighted": {
        const result = await callPythonBackend<WeightedAuditScore>(
          "/api/scoring/weighted",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Weighted scoring complete",
        );
        if (result.blockerFailures.length > 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: `📋 Weighted Audit Score Result:\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``,
              },
              {
                type: "text" as const,
                text:
                  `🛑 CERTIFICATION HALTED: ${result.blockerFailures.length} blocker failure(s) detected.\n` +
                  `Blocker(s): ${result.blockerFailures.join(", ")}\n` +
                  `Resolution required before certification can proceed. ` +
                  `Refer to the specific tool outputs above for remediation guidance.`,
              },
            ],
            isError: true as const,
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
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Certificate generation complete",
        );
        return formatSuccess(result, "Audit Certificate (W3C VC-JSON)");
      }

      // ── Tool 10: monitor_model_drift ────────────────────────────
      case "monitor_model_drift": {
        const result = await callPythonBackend<DriftReport>("/api/drift/monitor", {
          body: args,
          timeout: 120000,
        });
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Drift monitoring setup complete",
        );
        return formatSuccess(result, "Model Drift Report");
      }

      // ── Tool 11: audit_session_memory ─────────────────────────
      case "audit_session_memory": {
        const result = await callPythonBackend<SessionMemoryReport>(
          "/api/session-memory/audit",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Session memory audit complete",
        );
        return formatSuccess(result, "Session Memory Audit");
      }

      // ── Tool 12: audit_rag_quality ────────────────────────────
      case "audit_rag_quality": {
        const result = await callPythonBackend<RAGQualityReport>(
          "/api/rag-quality/evaluate",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "RAG quality evaluation complete",
        );
        return formatSuccess(result, "RAG Quality Report");
      }

      // ── Tool 13: audit_prompt_templates ────────────────────────
      case "audit_prompt_templates": {
        const result = await callPythonBackend<PromptAuditReport>(
          "/api/prompt-audit/evaluate",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Prompt template audit complete",
        );
        return formatSuccess(result, "Prompt Template Audit");
      }

      // ── Tool 14: audit_agent_trust ────────────────────────────
      case "audit_agent_trust": {
        const result = await callPythonBackend<AgentTrustReport>(
          "/api/agent-trust/evaluate",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Agent trust audit complete",
        );
        return formatSuccess(result, "Agent Trust Audit");
      }

      // ── Tool 15: audit_tool_permissions ────────────────────────
      case "audit_tool_permissions": {
        const result = await callPythonBackend<ToolPermissionReport>(
          "/api/tool-permissions/evaluate",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Tool permission audit complete",
        );
        return formatSuccess(result, "Tool Permission Audit");
      }

      // ── Tool 16: classify_agent_autonomy ──────────────────────
      case "classify_agent_autonomy": {
        const result = await callPythonBackend<AgentAutonomyResult>(
          "/api/agent-autonomy/classify",
          { body: args },
        );
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "Agent autonomy classification complete",
        );
        if (result.autonomyLevel === "fully_autonomous") {
          return {
            content: [
              {
                type: "text" as const,
                text: `📋 Agent Autonomy Classification Result:\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``,
              },
              {
                type: "text" as const,
                text:
                  "❌ BLOCKER FAIL: Fully autonomous agent detected. " +
                  "EU AI Act Art. 14 requires human oversight for high-risk AI systems. " +
                  "Autonomous operation without human oversight is PROHIBITED. " +
                  "Implement human-in-the-loop controls before deployment. " +
                  "See recommended controls in the result above.",
              },
            ],
            isError: true as const,
          };
        }
        return formatSuccess(result, "Agent Autonomy Classification");
      }

      // ── Tool 17: assess_dpdp_compliance ──────────────────────
      case "assess_dpdp_compliance": {
        const result = await callPythonBackend<DPDPComplianceReport>("/api/dpdp/assess", {
          body: args,
        });
        await sendProgress(
          extra?.sendNotification?.bind(extra) || (async () => {}),
          progressToken,
          100,
          100,
          "DPDP compliance assessment complete",
        );
        return formatSuccess(result, "India DPDP Act 2023 Compliance Report");
      }

      default:
        return mcpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: "${name}". Use ListTools to see available tools.`,
          { availableTools: TOOLS.map((t) => t.name) },
        );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    // Map HTTP errors to MCP error codes
    if (message.includes("Authentication failed (401)")) {
      return mcpError(ErrorCode.InternalError, `Authentication error: ${message}`);
    }
    if (message.includes("Authorization failed (403)")) {
      return mcpError(ErrorCode.InternalError, `Authorization error: ${message}`);
    }
    if (message.includes("timed out")) {
      return mcpError(ErrorCode.InternalError, `Timeout: ${message}`);
    }
    if (message.includes("Python backend error (422)")) {
      return mcpError(ErrorCode.InvalidParams, `Validation error from backend: ${message}`);
    }
    if (message.includes("Python backend error (5")) {
      return mcpError(ErrorCode.InternalError, `Backend server error: ${message}`);
    }

    return mcpError(ErrorCode.InternalError, `Error executing tool "${name}": ${message}`);
  }
});

// ═══════════════════════════════════════════════════════════════════
//  DNS-Rebinding Protection: Origin Validation Middleware
// ═══════════════════════════════════════════════════════════════════

export function validateOrigin(allowedOrigins: string[]) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const origin = req.headers.origin;
    if (!origin) return next();
    const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
    if (isLocalhost || allowedOrigins.includes(origin)) return next();
    res.status(403).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: `Origin '${origin}' is not allowed` },
      id: null,
    });
  };
}

// ═══════════════════════════════════════════════════════════════════
//  TRANSPORT: Start MCP Server
// ═══════════════════════════════════════════════════════════════════

async function main() {
  const transportType = process.env.MCP_TRANSPORT || "stdio";
  const host = process.env.MCP_HTTP_HOST || "127.0.0.1";
  const allowedOrigins = process.env.MCP_ALLOWED_ORIGINS?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];

  if (transportType === "sse") {
    // ── SSE Transport ────────────────────────────────────────────
    const app = express();
    app.use(express.json());
    const sseOriginGuard = validateOrigin(allowedOrigins);
    const transports: Map<string, SSEServerTransport> = new Map();

    app.get("/health", (_req, res) => {
      res.json({
        status: "ok",
        transport: "sse",
        sessionCount: transports.size,
        version: SERVER_VERSION,
        capabilities: ["tools", "resources", "prompts"],
      });
    });

    app.get("/sse", sseOriginGuard, async (req, res) => {
      const transport = new SSEServerTransport("/messages", res);
      const sessionId = transport.sessionId;
      transports.set(sessionId, transport);
      res.on("close", () => transports.delete(sessionId));
      await server.connect(transport);
    });

    app.post("/messages", sseOriginGuard, async (req, res) => {
      const sessionId = req.query.sessionId as string;
      const transport = transports.get(sessionId);
      if (transport) {
        await transport.handlePostMessage(req, res);
      } else {
        res.status(404).json({
          jsonrpc: "2.0",
          error: { code: -32001, message: "Session not found" },
          id: null,
        });
      }
    });

    const port = parseInt(process.env.PORT || "3000", 10);
    app.listen(port, host, () => {
      console.error(`[ComplianceStack MCP] SSE transport listening on ${host}:${port}`);
    });
  } else if (transportType === "streamable-http") {
    // ── Streamable HTTP Transport (True MCP Implementation) ─────
    // Uses custom StreamableHTTPTransport that implements the MCP
    // Transport interface directly, rather than wrapping SSEServerTransport.
    //
    // Protocol:
    //   POST /mcp   — JSON-RPC messages (application/json or x-ndjson)
    //   GET  /mcp   — SSE stream for server-initiated messages
    //   DELETE /mcp — Session termination
    import("./streamable-http-transport.js").then(
      ({ StreamableHTTPSessionManager }) => {
        const app = express();
        app.use(express.json({ limit: "10mb" }));
        const originGuard = validateOrigin(allowedOrigins);
        const sessionManager = new StreamableHTTPSessionManager();
        sessionManager.startCleanup();

        app.get("/", async (_req, res) => {
          const { renderWorkbenchShell } = await import("./workbench.js");
          res.type("html").send(renderWorkbenchShell(SERVER_VERSION));
        });

        app.get("/assets/workbench.js", async (_req, res) => {
          const { getWorkbenchJs } = await import("./workbench.js");
          res.type("application/javascript").send(getWorkbenchJs());
        });

        app.get("/assets/workbench.css", async (_req, res) => {
          const { getWorkbenchCss } = await import("./workbench.js");
          res.type("text/css").send(getWorkbenchCss());
        });

        app.get("/status", async (_req, res) => {
          const { buildStatusPage } = await import("./status-page.js");
          res.type("html").send(await buildStatusPage(sessionManager.sessionCount, SERVER_VERSION));
        });

        app.get("/health", (_req, res) => {
          res.json({
            status: "ok",
            transport: "streamable-http",
            sessionCount: sessionManager.sessionCount,
            version: SERVER_VERSION,
            capabilities: ["tools", "resources", "prompts"],
            mcpEndpoint: "/mcp",
          });
        });

        // POST /mcp — Main MCP endpoint
        app.post("/mcp", originGuard, async (req, res) => {
          const sessionId = req.headers["mcp-session-id"] as string | undefined;

          if (!sessionId) {
            // Create new session
            const session = sessionManager.createSession();
            const transport = session.transport;
            await server.connect(transport);

            res.setHeader("mcp-session-id", session.id);
            // Note: the session must NOT be terminated when this initial POST
            // response closes — the session is expected to live across
            // subsequent POSTs and the SSE GET stream. Idle sessions are
            // reaped by `sessionManager.startCleanup()`; explicit termination
            // happens on `DELETE /mcp`.

            await transport.handlePostMessage(req, res);
            console.error(`[ComplianceStack MCP] New session: ${session.id}`);
            return;
          }

          // Route to existing session
          const session = sessionManager.getSession(sessionId);
          if (!session) {
            res.status(404).json({
              jsonrpc: "2.0",
              error: { code: -32001, message: `Session not found: ${sessionId}` },
              id: null,
            });
            return;
          }

          await session.transport.handlePostMessage(req, res);
        });

        // GET /mcp — SSE stream for server-initiated messages
        app.get("/mcp", originGuard, async (req, res) => {
          const sessionId = req.headers["mcp-session-id"] as string | undefined;
          if (!sessionId) {
            res.status(400).json({ error: "mcp-session-id header required" });
            return;
          }

          const session = sessionManager.getSession(sessionId);
          if (!session) {
            res.status(404).json({ error: "Session not found" });
            return;
          }

          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
            "X-Accel-Buffering": "no",
          });

          res.write(`event: connected\ndata: ${JSON.stringify({ sessionId })}\n\n`);

          session.transport.attachSSE(res);

          const heartbeat = setInterval(() => {
            try {
              res.write(`:heartbeat\n\n`);
            } catch {
              clearInterval(heartbeat);
            }
          }, 30000);

          res.on("close", () => {
            clearInterval(heartbeat);
            session.transport.detachSSE(res);
            console.error(`[ComplianceStack MCP] SSE closed for ${sessionId} (session kept alive; idle cleanup handles GC)`);
          });
        });

        // DELETE /mcp — Session termination
        app.delete("/mcp", originGuard, async (req, res) => {
          const sessionId = req.headers["mcp-session-id"] as string | undefined;
          if (sessionId) {
            const terminated = await sessionManager.terminateSession(sessionId);
            if (terminated) {
              res.status(200).json({ ok: true });
            } else {
              res.status(404).json({ error: "Session not found" });
            }
          } else {
            res.status(400).json({ error: "mcp-session-id header required" });
          }
        });

        const port = parseInt(process.env.PORT || "3000", 10);
        app.listen(port, host, () => {
          console.error(`[ComplianceStack MCP] Streamable HTTP transport on ${host}:${port}`);
        });
      }
    );
  } else {
    // ── Stdio Transport ──────────────────────────────────────────
    const transport = new StdioServerTransport();
    console.error(`[ComplianceStack MCP] Starting with stdio transport (v${SERVER_VERSION})...`);
    await server.connect(transport);
  }
}

main().catch((error) => {
  console.error(`[ComplianceStack MCP] Fatal error:`, error);
  process.exit(1);
});
