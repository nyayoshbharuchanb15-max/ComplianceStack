// SPDX-License-Identifier: Apache-2.0
// ═══════════════════════════════════════════════════════════════════
//  Governance Pipeline MCP Tools — 9 phases + reaudit + run status
//  Contracts: AUDIT_PIPELINE.md (source of truth). Each tool maps to a
//  FastAPI orchestrator route and a least-privilege scope. Inputs are
//  validated against strict JSON Schema and the token scope is checked
//  BEFORE the orchestrator is invoked.
// ═══════════════════════════════════════════════════════════════════

import { Ajv, type ValidateFunction } from "ajv";
import type { ToolSchemaEntry } from "./tool-schemas.js";
import {
  callGovernance,
  GovernanceAuthzError,
} from "./governance-client.js";

const MODEL_ID = {
  type: "string",
  minLength: 1,
  maxLength: 255,
  pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
  description: "Unique model identifier",
} as const;

const RUN_ID = {
  type: "string",
  minLength: 8,
  maxLength: 64,
  description: "Audit run identifier returned by intake_register",
} as const;

export const GOVERNANCE_TOOL_SCHEMAS: ToolSchemaEntry[] = [
  // Phase 1
  {
    name: "intake_register",
    description:
      "Phase 1/9 — Intake & Context Registration. Registers the model, its processing " +
      "activities and datasets; creates the audit run and the lineage graph root. " +
      "🔗 EU AI Act Art. 11 | GDPR Art. 30 | ISO/IEC 42001 Clause 7.5 | NIST AI RMF MAP 1.1",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID,
        modelVersion: { type: "string", minLength: 1, maxLength: 100 },
        ownerTeam: { type: "string", maxLength: 255, default: "" },
        deploymentContext: {
          type: "object",
          properties: {
            sector: { type: "string", maxLength: 100, default: "other" },
            regions: { type: "array", items: { type: "string", minLength: 2, maxLength: 5 }, maxItems: 20, default: [] },
            autonomyLevel: { type: "string", enum: ["assistive", "supervised", "autonomous"], default: "assistive" },
            description: { type: "string", maxLength: 2000 },
          },
          additionalProperties: false,
        },
        processingActivities: {
          type: "array",
          maxItems: 50,
          items: {
            type: "object",
            properties: {
              name: { type: "string", minLength: 1, maxLength: 255 },
              purpose: { type: "string", minLength: 1, maxLength: 1000 },
              dataCategories: { type: "array", items: { type: "string" }, maxItems: 50, default: [] },
              dataSubjects: { type: "array", items: { type: "string" }, maxItems: 50, default: [] },
              crossBorder: { type: "boolean", default: false },
              specialCategories: { type: "array", items: { type: "string" }, maxItems: 20, default: [] },
            },
            required: ["name", "purpose"],
            additionalProperties: false,
          },
          default: [],
        },
        datasets: {
          type: "array",
          maxItems: 50,
          items: {
            type: "object",
            properties: {
              datasetId: { type: "string", minLength: 1, maxLength: 255 },
              version: { type: "string", maxLength: 100, default: "1" },
              containsPersonalData: { type: "boolean", default: false },
              name: { type: "string", maxLength: 255 },
              specialCategories: { type: "array", items: { type: "string" }, maxItems: 20, default: [] },
            },
            required: ["datasetId"],
            additionalProperties: false,
          },
          default: [],
        },
        evidenceArtifacts: {
          type: "array",
          maxItems: 200,
          description:
            "Compliance documents/records submitted as evidence for this audit run — cited by every phase " +
            "against the specific regulatory articles they evidence. Types: model_card, dpia, dataset_lineage, " +
            "bias_test_output, robustness_test_log, explainability_report, oversight_procedure, etc.",
          items: {
            type: "object",
            properties: {
              artifactId: { type: "string", maxLength: 100 },
              name: { type: "string", minLength: 1, maxLength: 500 },
              type: {
                type: "string",
                pattern: "^[a-z_]+$",
                maxLength: 100,
                description: "Artifact category (see PHASE_EXPECTATIONS in orchestrator/citations.py).",
              },
              uri: { type: "string", maxLength: 1000 },
              mimeType: { type: "string", maxLength: 150 },
              contentSnippet: { type: "string", maxLength: 4000 },
              sha256: { type: "string", maxLength: 64 },
              sizeBytes: { type: "integer", minimum: 0 },
              tags: { type: "array", items: { type: "string" }, maxItems: 20, default: [] },
            },
            required: ["name", "type"],
            additionalProperties: false,
          },
          default: [],
        },
      },
      required: ["modelId", "modelVersion"],
      additionalProperties: false,
    },
  },
  // Phase 2
  {
    name: "map_regulatory_scope",
    description:
      "Phase 2/9 — Regulatory Scope Mapping. Derives article-level applicability of the EU AI Act, " +
      "GDPR, DPDP Act, NIST AI RMF and ISO/IEC 42001 from the registered intake context. " +
      "🔗 All five frameworks — article-level scope map with triggers",
    inputSchema: {
      type: "object",
      properties: { runId: RUN_ID },
      required: ["runId"],
      additionalProperties: false,
    },
  },
  // Phase 3
  {
    name: "classify_risk",
    description:
      "Phase 3/9 — Risk Classification. Deterministic EU AI Act tiering (prohibited/high/limited/minimal). " +
      "A prohibited practice is a BLOCKER that halts the pipeline. " +
      "🔗 EU AI Act Art. 5, Art. 6 + Annex III, Art. 50 | NIST AI RMF MAP 1.1",
    inputSchema: {
      type: "object",
      properties: {
        runId: RUN_ID,
        riskInputs: {
          type: "object",
          properties: {
            usesRealtimeBiometricId: { type: "boolean", default: false },
            usesSocialScoring: { type: "boolean", default: false },
            usesManipulativeTechniques: { type: "boolean", default: false },
            isSafetyComponent: { type: "boolean", default: false },
            annexIIICategories: {
              type: "array",
              items: {
                type: "string",
                enum: ["biometric_identification", "critical_infrastructure", "education",
                  "employment", "essential_services", "law_enforcement",
                  "migration_border", "justice_democracy"],
              },
              uniqueItems: true,
              maxItems: 8,
              default: [],
            },
            interactsWithHumans: { type: "boolean", default: false },
            generatesSyntheticContent: { type: "boolean", default: false },
          },
          additionalProperties: false,
        },
      },
      required: ["runId"],
      additionalProperties: false,
    },
  },
  // Phase 4
  {
    name: "check_data_protection",
    description:
      "Phase 4/9 — Data Protection & Privacy Checks. Article-level GDPR + DPDP findings; " +
      "missing lawful basis, uncovered Art. 9 data, unlawful transfers or a missing DPIA are BLOCKERs. " +
      "🔗 GDPR Art. 5, 6, 9, 22, 25, 30, 35, 44–49 | DPDP Act Sec. 6, 8, 10",
    inputSchema: {
      type: "object",
      properties: {
        runId: RUN_ID,
        dataProtection: {
          type: "object",
          properties: {
            processesPersonalData: { type: "boolean", default: false },
            lawfulBasis: { type: "string", enum: ["consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests", "none"], default: "none" },
            specialCategoryBasis: { type: "string", enum: ["explicit_consent", "employment_law", "vital_interests", "substantial_public_interest", "health", "none"], default: "none" },
            dpiaConducted: { type: "boolean", default: false },
            dpoAppointed: { type: "boolean", default: false },
            consentMechanism: { type: "boolean", default: false },
            crossBorderTransfers: {
              type: "array",
              maxItems: 50,
              items: {
                type: "object",
                properties: {
                  destination: { type: "string", minLength: 1, maxLength: 100 },
                  mechanism: { type: "string", enum: ["adequacy_decision", "scc", "bcr", "none"], default: "none" },
                },
                required: ["destination"],
                additionalProperties: false,
              },
              default: [],
            },
            retentionPeriodDays: { type: "integer", minimum: 1, maximum: 36500 },
            dataMinimisationApplied: { type: "boolean", default: false },
            privacyByDesign: { type: "boolean", default: false },
          },
          additionalProperties: false,
        },
      },
      required: ["runId"],
      additionalProperties: false,
    },
  },
  // Phase 5
  {
    name: "evaluate_fairness",
    description:
      "Phase 5/9 — Fairness & Bias Evaluation. Deterministic demographic parity, disparate impact " +
      "and equal opportunity from an in-boundary dataset sample. Disparate impact below the " +
      "threshold (four-fifths rule) is a BLOCKER. " +
      "🔗 EU AI Act Art. 10 | GDPR Art. 5(1)(a) | NIST AI RMF MEASURE 2.2",
    inputSchema: {
      type: "object",
      properties: {
        runId: RUN_ID,
        datasetSample: {
          type: "array",
          minItems: 2,
          maxItems: 10000,
          items: {
            type: "object",
            properties: {
              attributes: { type: "object" },
              outcome: { type: "integer", minimum: 0, maximum: 1 },
              label: { type: "integer", minimum: 0, maximum: 1 },
            },
            required: ["attributes", "outcome"],
            additionalProperties: false,
          },
        },
        sensitiveFeatures: { type: "array", items: { type: "string", minLength: 1 }, minItems: 1, maxItems: 20, uniqueItems: true },
        fairnessThreshold: { type: "number", minimum: 0, maximum: 1, default: 0.8 },
      },
      required: ["runId", "datasetSample", "sensitiveFeatures"],
      additionalProperties: false,
    },
  },
  // Phase 6
  {
    name: "test_robustness",
    description:
      "Phase 6/9 — Robustness, Security & Resilience. Local deterministic attack corpora " +
      "(prompt injection, jailbreak, data extraction, evasion, poisoning). Critical-suite " +
      "resistance below 0.5 is a BLOCKER. No payload leaves the deployment boundary. " +
      "🔗 EU AI Act Art. 15 | NIST AI RMF MEASURE 2.7 | ISO/IEC 42001 Clause 8.1.3",
    inputSchema: {
      type: "object",
      properties: {
        runId: RUN_ID,
        testSuites: {
          type: "array",
          items: { type: "string", enum: ["prompt_injection", "jailbreak", "data_extraction", "evasion", "poisoning_resilience"] },
          minItems: 1,
          maxItems: 5,
          uniqueItems: true,
        },
        securityControls: {
          type: "object",
          properties: {
            inputSanitization: { type: "boolean", default: false },
            outputFiltering: { type: "boolean", default: false },
            rateLimiting: { type: "boolean", default: false },
            adversarialTraining: { type: "boolean", default: false },
            anomalyMonitoring: { type: "boolean", default: false },
            accessControl: { type: "boolean", default: false },
          },
          additionalProperties: false,
        },
      },
      required: ["runId", "testSuites"],
      additionalProperties: false,
    },
  },
  // Phase 7
  {
    name: "verify_explainability",
    description:
      "Phase 7/9 — Explainability & Human Oversight. For high-risk systems, a missing kill switch, " +
      "missing human oversight, no explainability method or no decision logs are BLOCKERs. " +
      "🔗 EU AI Act Art. 12, 13, 14, 86 | GDPR Art. 22",
    inputSchema: {
      type: "object",
      properties: {
        runId: RUN_ID,
        oversight: {
          type: "object",
          properties: {
            hasHumanInTheLoop: { type: "boolean", default: false },
            hasKillSwitch: { type: "boolean", default: false },
            overrideProcedureDocumented: { type: "boolean", default: false },
            oversightRoles: { type: "array", items: { type: "string" }, maxItems: 20, default: [] },
          },
          additionalProperties: false,
        },
        explainability: {
          type: "object",
          properties: {
            method: { type: "string", enum: ["shap", "lime", "integrated_gradients", "attention_maps", "rule_based", "none"], default: "none" },
            userFacingExplanations: { type: "boolean", default: false },
            decisionLogsRetained: { type: "boolean", default: false },
            logRetentionDays: { type: "integer", minimum: 1, maximum: 36500 },
          },
          additionalProperties: false,
        },
      },
      required: ["runId"],
      additionalProperties: false,
    },
  },
  // Phase 8
  {
    name: "assemble_certification",
    description:
      "Phase 8/9 — Certification Assembly. Issues a W3C Verifiable Credential 2.0 " +
      "(DataIntegrityProof, eddsa-jcs-2022, Ed25519) embedding per-phase integrity hashes, " +
      "evidence IDs and article references. Hard gate: any blocker in the run prohibits issuance. " +
      "🔗 W3C VC 2.0 | ISO/IEC 42001 Clause 9.1 | schemas/w3c_audit_credential.jsonld",
    inputSchema: {
      type: "object",
      properties: {
        runId: RUN_ID,
        issuer: {
          type: "object",
          properties: {
            name: { type: "string", minLength: 1, maxLength: 255, default: "AI Governance Authority" },
            contact: { type: "string", maxLength: 255 },
          },
          additionalProperties: false,
        },
        validityDays: { type: "integer", minimum: 1, maximum: 3650, default: 365 },
      },
      required: ["runId"],
      additionalProperties: false,
    },
  },
  // Phase 9
  {
    name: "configure_monitoring",
    description:
      "Phase 9/9 — Continuous Monitoring & Reaudit Triggering. Arms drift/fairness thresholds and " +
      "reaudit triggers; production observations breaching thresholds publish reaudit events on " +
      "the internal governance:reaudit stream. " +
      "🔗 EU AI Act Art. 72, 15 | ISO/IEC 42001 Clause 9.1 | NIST AI RMF MEASURE 3.3",
    inputSchema: {
      type: "object",
      properties: {
        runId: RUN_ID,
        monitors: {
          type: "object",
          properties: {
            driftThreshold: { type: "number", minimum: 0, maximum: 1, default: 0.2 },
            fairnessDriftThreshold: { type: "number", minimum: 0, maximum: 1, default: 0.1 },
            reauditTriggers: {
              type: "array",
              items: { type: "string", enum: ["model_version_change", "dataset_revision", "policy_update", "critical_incident", "drift_threshold_breach"] },
              uniqueItems: true,
              maxItems: 5,
            },
          },
          additionalProperties: false,
        },
      },
      required: ["runId"],
      additionalProperties: false,
    },
  },
  // Reaudit
  {
    name: "trigger_reaudit",
    description:
      "Reaudit Pattern — resolves the impact scope in the Neo4j control graph, re-runs only " +
      "impacted phases + dependent controls against stored immutable inputs, diffs old vs new " +
      "findings and re-issues/supersedes/revokes the certificate accordingly. " +
      "🔗 ARCHITECTURE.md §7 | AUDIT_PIPELINE.md §11",
    inputSchema: {
      type: "object",
      properties: {
        modelId: MODEL_ID,
        trigger: {
          type: "object",
          properties: {
            type: { type: "string", enum: ["model_version_change", "dataset_revision", "policy_update", "critical_incident", "drift_threshold_breach"] },
            detail: { type: "string", maxLength: 2000, default: "" },
            datasetId: { type: "string", maxLength: 255 },
            newModelVersion: { type: "string", maxLength: 100 },
            policyReference: { type: "string", maxLength: 255 },
            updatedPhaseInputs: {
              type: "object",
              description: "Optional map of phase key → revised inputs (trigger deltas, e.g. revised dataset sample)",
            },
          },
          required: ["type"],
          additionalProperties: false,
        },
      },
      required: ["modelId", "trigger"],
      additionalProperties: false,
    },
  },
  // Run status
  {
    name: "get_audit_run",
    description:
      "Returns the phase state machine status of an audit run: per-phase status, integrity hash " +
      "chain, evidence IDs, blockers and the issued certificate ID (if any).",
    inputSchema: {
      type: "object",
      properties: { runId: RUN_ID },
      required: ["runId"],
      additionalProperties: false,
    },
  },
];

// tool → orchestrator route + required scope (least privilege)
const TOOL_ROUTING: Record<string, { path: string; scope: string; label: string }> = {
  intake_register: { path: "/api/v1/phases/intake", scope: "phase:intake", label: "Phase 1 — Intake & Context Registration" },
  map_regulatory_scope: { path: "/api/v1/phases/scope", scope: "phase:scope", label: "Phase 2 — Regulatory Scope Mapping" },
  classify_risk: { path: "/api/v1/phases/risk", scope: "phase:risk", label: "Phase 3 — Risk Classification" },
  check_data_protection: { path: "/api/v1/phases/data-protection", scope: "phase:privacy", label: "Phase 4 — Data Protection & Privacy" },
  evaluate_fairness: { path: "/api/v1/phases/fairness", scope: "phase:fairness", label: "Phase 5 — Fairness & Bias Evaluation" },
  test_robustness: { path: "/api/v1/phases/robustness", scope: "phase:robustness", label: "Phase 6 — Robustness, Security & Resilience" },
  verify_explainability: { path: "/api/v1/phases/explainability", scope: "phase:explainability", label: "Phase 7 — Explainability & Human Oversight" },
  assemble_certification: { path: "/api/v1/phases/certification", scope: "phase:certify", label: "Phase 8 — Certification Assembly (VC 2.0)" },
  configure_monitoring: { path: "/api/v1/phases/monitoring", scope: "phase:monitor", label: "Phase 9 — Continuous Monitoring" },
  trigger_reaudit: { path: "/api/v1/reaudit", scope: "reaudit:trigger", label: "Reaudit — Impact Scope Resolution" },
  get_audit_run: { path: "/api/v1/runs", scope: "runs:read", label: "Audit Run Status" },
};

const ajv = new Ajv({ allErrors: true, strict: false, useDefaults: false });
const validators = new Map<string, ValidateFunction>();
for (const tool of GOVERNANCE_TOOL_SCHEMAS) {
  validators.set(tool.name, ajv.compile(tool.inputSchema));
}

export function isGovernanceTool(name: string): boolean {
  return name in TOOL_ROUTING;
}

export function governanceToolScope(name: string): string | undefined {
  return TOOL_ROUTING[name]?.scope;
}

export function validateGovernanceInput(
  name: string,
  args: Record<string, unknown>,
): { valid: boolean; errors: string[] } {
  const validate = validators.get(name);
  if (!validate) return { valid: false, errors: [`Unknown governance tool: ${name}`] };
  if (validate(args)) return { valid: true, errors: [] };
  return {
    valid: false,
    errors: (validate.errors || []).map((e) => `${e.instancePath || "/"} ${e.message}`),
  };
}

type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: true;
};

function textError(message: string): ToolResult {
  return { content: [{ type: "text", text: message }], isError: true as const };
}

export async function handleGovernanceTool(
  name: string,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const routing = TOOL_ROUTING[name];

  // 1. Schema validation — malformed requests rejected before FastAPI
  const validation = validateGovernanceInput(name, args);
  if (!validation.valid) {
    return textError(
      `❌ Input validation failed for '${name}' (rejected at MCP layer): ${validation.errors.join("; ")}`,
    );
  }

  try {
    // 2. Authorization (scope check) happens inside callGovernance BEFORE the HTTP call
    let result: unknown;
    if (name === "get_audit_run") {
      result = await callGovernance(
        `${routing.path}/${encodeURIComponent(String(args.runId))}`,
        routing.scope,
        undefined,
        "GET",
      );
    } else {
      result = await callGovernance(routing.path, routing.scope, args, "POST", 120_000);
    }

    const body = `📋 ${routing.label} Result:\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\``;
    const envelope = result as { status?: string; blockers?: Array<{ code: string; reason: string; remediation: string }> };
    if (envelope.status === "blocked" && envelope.blockers?.length) {
      const details = envelope.blockers
        .map((b) => `• [${b.code}] ${b.reason} Remediation: ${b.remediation}`)
        .join("\n");
      return {
        content: [
          { type: "text" as const, text: body },
          {
            type: "text" as const,
            text:
              `🛑 BLOCKER — pipeline halted deterministically. Certificate issuance is now ` +
              `prohibited for this run.\n${details}`,
          },
        ],
        isError: true as const,
      };
    }
    return { content: [{ type: "text" as const, text: body }] };
  } catch (error) {
    if (error instanceof GovernanceAuthzError) {
      return textError(`🔒 ${error.message}`);
    }
    const message = error instanceof Error ? error.message : String(error);
    return textError(`Error executing governance tool '${name}': ${message}`);
  }
}
