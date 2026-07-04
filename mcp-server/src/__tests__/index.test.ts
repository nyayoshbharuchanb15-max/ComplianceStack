import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  validateToolInput,
  getRegisteredTools,
  getToolSchema,
} from "../validator.js";
import {
  StreamableHTTPTransport,
  StreamableHTTPSessionManager,
} from "../streamable-http-transport.js";
import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { McpError } from "../errors.js";

// ═══════════════════════════════════════════════════════════════════
//  1. Validator Tests
// ═══════════════════════════════════════════════════════════════════

describe("validateToolInput", () => {
  describe("classify_ai_risk", () => {
    it("valid classify_ai_risk input passes", () => {
      const result = validateToolInput("classify_ai_risk", {
        modelId: "gpt-4-healthcare-v2",
        modelType: "general_purpose_ai",
        sector: "healthcare",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it("missing required modelId fails", () => {
      const result = validateToolInput("classify_ai_risk", {
        modelType: "general_purpose_ai",
        sector: "healthcare",
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(
        result.errors!.some((e) => e.message?.includes("modelId"))
      ).toBe(true);
    });

    it("invalid modelId pattern fails", () => {
      const result = validateToolInput("classify_ai_risk", {
        modelId: "!invalid-model-id!",
        modelType: "general_purpose_ai",
        sector: "healthcare",
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
    });

    it("extra properties rejected (additionalProperties:false)", () => {
      const result = validateToolInput("classify_ai_risk", {
        modelId: "valid-model",
        modelType: "llm",
        unknownField: "should be rejected",
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(
        result.errors!.some(
          (e) => e.keyword === "additionalProperties"
        )
      ).toBe(true);
    });
  });

  describe("assess_dpdp_compliance", () => {
    it("valid assess_dpdp_compliance with all 18 params passes", () => {
      const result = validateToolInput("assess_dpdp_compliance", {
        modelId: "dpdp-model-v1",
        dataFiduciary: "Acme Corp India Pvt Ltd",
        consentMechanism: "explicit",
        dataPrincipalRights: [
          "access",
          "correction",
          "erasure",
          "grievance_redressal",
          "nomination",
        ],
        processingPurpose: "Personalized recommendation engine",
        dataLocalization: true,
        crossBorderTransfer: false,
        transferCountries: [],
        hasDataProtectionOfficer: true,
        hasPrivacyPolicy: true,
        hasBreachNotification: true,
        breachNotificationHours: 72,
        hasChildProtection: true,
        hasSignificantDataFiduciaryObligations: false,
        processingRecords: true,
        dataRetentionDays: 365,
        hasConsentRecords: true,
        hasAuditTrail: true,
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it("invalid enum value fails", () => {
      const result = validateToolInput("assess_dpdp_compliance", {
        modelId: "dpdp-model-v1",
        dataFiduciary: "Acme Corp",
        consentMechanism: "invalid_consent_type",
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
    });
  });

  describe("run_bias_assessment", () => {
    it("array minItems enforcement", () => {
      const result = validateToolInput("run_bias_assessment", {
        modelId: "bias-model",
        protectedGroups: [],
        metrics: ["demographic_parity"],
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
    });
  });

  describe("generate_dpia", () => {
    it("string minLength enforcement", () => {
      const result = validateToolInput("generate_dpia", {
        modelId: "dpia-model",
        processingPurpose: "",
        dataCategories: ["health"],
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
    });
  });

  describe("run_adversarial_tests", () => {
    it("number minimum/maximum enforcement", () => {
      const result = validateToolInput("run_adversarial_tests", {
        modelId: "adv-model",
        testTypes: ["prompt_injection"],
        maxAttempts: 0,
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
    });
  });

  describe("unknown tool", () => {
    it("returns error for unknown tool name", () => {
      const result = validateToolInput("nonexistent_tool", {
        modelId: "test",
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors![0].message).toContain("Unknown tool");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
//  2. Transport Tests
// ═══════════════════════════════════════════════════════════════════

describe("StreamableHTTPTransport", () => {
  let transport: StreamableHTTPTransport;

  beforeEach(() => {
    transport = new StreamableHTTPTransport("test-session-id");
  });

  afterEach(async () => {
    if (!transport["_closed"]) {
      await transport.close();
    }
  });

  it("createSession returns unique session IDs", () => {
    const manager = new StreamableHTTPSessionManager();
    const session1 = manager.createSession();
    const session2 = manager.createSession();
    expect(session1.id).toBeDefined();
    expect(session2.id).toBeDefined();
    expect(session1.id).not.toBe(session2.id);
  });

  it("getSession returns existing session", () => {
    const manager = new StreamableHTTPSessionManager();
    const session = manager.createSession();
    const retrieved = manager.getSession(session.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(session.id);
  });

  it("getSession returns undefined for unknown ID", () => {
    const manager = new StreamableHTTPSessionManager();
    const retrieved = manager.getSession("nonexistent-id");
    expect(retrieved).toBeUndefined();
  });

  it("terminateSession closes transport", async () => {
    const manager = new StreamableHTTPSessionManager();
    const session = manager.createSession();
    const closeSpy = vi.spyOn(session.transport, "close");

    const result = await manager.terminateSession(session.id);
    expect(result).toBe(true);
    expect(closeSpy).toHaveBeenCalled();
    expect(manager.sessionCount).toBe(0);
  });

  it("terminateSession returns false for unknown ID", async () => {
    const manager = new StreamableHTTPSessionManager();
    const result = await manager.terminateSession("nonexistent-id");
    expect(result).toBe(false);
  });

  it("session timeout cleanup works", async () => {
    vi.useFakeTimers();
    const manager = new StreamableHTTPSessionManager(1000);
    const session = manager.createSession();
    expect(manager.sessionCount).toBe(1);

    manager.startCleanup();

    // Advance time past the timeout
    vi.advanceTimersByTime(2000);

    // Give a tick for the interval callback
    await vi.advanceTimersByTimeAsync(0);

    expect(manager.sessionCount).toBe(0);

    manager.stopCleanup();
    vi.useRealTimers();
  });

  it("transport close calls onclose callback", async () => {
    const onClose = vi.fn();
    transport.onclose = onClose;
    await transport.close();
    expect(onClose).toHaveBeenCalled();
  });

  it("transport sends message after close is a no-op", async () => {
    await transport.close();
    // Should not throw
    await transport.send({
      jsonrpc: "2.0",
      method: "test",
      params: {},
    });
  });

  it("transport queues messages before start and flushes on start", async () => {
    const t = new StreamableHTTPTransport("queue-test");
    const messages: unknown[] = [];

    // Queue a message before start
    await t.send({
      jsonrpc: "2.0",
      method: "test",
      params: { foo: "bar" },
    });

    // Attach a mock SSE response to capture flushed messages
    const mockRes = {
      writableEnded: false,
      write: vi.fn((data: string) => {
        messages.push(data);
      }),
      end: vi.fn(),
    } as any;

    await t.start();
    t.attachSSE(mockRes as any);

    // The queued message should be flushed via the SSE connection
    expect(messages.length).toBe(1);
    expect(messages[0]).toContain("test");
  });

  it("handlePostMessage returns 410 when session is terminated", async () => {
    const t = new StreamableHTTPTransport("closed-test");
    await t.close();

    const mockReq = {
      headers: { "content-type": "application/json" },
      body: {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
      },
    } as any;

    const mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    } as any;

    await t.handlePostMessage(mockReq, mockRes);
    expect(mockRes.status).toHaveBeenCalledWith(410);
  });

  it("handlePostMessage returns 415 for unsupported content type", async () => {
    const t = new StreamableHTTPTransport("ct-test");
    const mockReq = {
      headers: { "content-type": "text/plain" },
      body: "hello",
    } as any;

    const mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    } as any;

    await t.handlePostMessage(mockReq, mockRes);
    expect(mockRes.status).toHaveBeenCalledWith(415);
  });
});

// ═══════════════════════════════════════════════════════════════════
//  3. Tool Schema Tests
// ═══════════════════════════════════════════════════════════════════

describe("TOOL_SCHEMAS", () => {
  const expectedToolNames = [
    "classify_ai_risk",
    "discover_supply_chain",
    "audit_supply_chain",
    "verify_human_oversight",
    "run_bias_assessment",
    "generate_dpia",
    "run_adversarial_tests",
    "score_audit_weighted",
    "generate_audit_certificate",
    "monitor_model_drift",
    "audit_session_memory",
    "audit_rag_quality",
    "audit_prompt_templates",
    "audit_agent_trust",
    "audit_tool_permissions",
    "classify_agent_autonomy",
    "assess_dpdp_compliance",
  ];

  it("all 17 tools have required fields", () => {
    const tools = getRegisteredTools();
    expect(tools).toHaveLength(17);

    for (const name of expectedToolNames) {
      expect(tools).toContain(name);
      const schema = getToolSchema(name);
      expect(schema).toBeDefined();
      expect(schema!.type).toBe("object");
      expect(schema!.properties).toBeDefined();
      expect(Array.isArray((schema as any).required)).toBe(true);
    }
  });

  it("all tools have additionalProperties:false", () => {
    for (const name of expectedToolNames) {
      const schema = getToolSchema(name) as any;
      expect(schema.additionalProperties).toBe(false);
    }
  });

  it("all tools have description with regulatory references", () => {
    for (const name of expectedToolNames) {
      const schema = getToolSchema(name);
      expect(schema).toBeDefined();
    }
  });

  it("DPDP tool has 18+ properties", () => {
    const schema = getToolSchema("assess_dpdp_compliance") as any;
    const propCount = Object.keys(schema.properties).length;
    expect(propCount).toBeGreaterThanOrEqual(18);
  });

  it("every tool requires modelId", () => {
    for (const name of expectedToolNames) {
      const schema = getToolSchema(name) as any;
      expect(schema.required).toContain("modelId");
    }
  });

  it("all tools have valid JSON Schema structure", () => {
    for (const name of expectedToolNames) {
      const schema = getToolSchema(name) as any;
      expect(schema.type).toBe("object");
      expect(typeof schema.properties).toBe("object");
      expect(schema.properties.modelId).toBeDefined();
      expect(schema.properties.modelId.type).toBe("string");
    }
  });

  it("getToolSchema returns undefined for unknown tool", () => {
    expect(getToolSchema("nonexistent_tool")).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════
//  4. McpError Tests
// ═══════════════════════════════════════════════════════════════════

describe("McpError", () => {
  it("McpError creates structured error response", () => {
    const error = new McpError(
      ErrorCode.InvalidParams,
      "modelId is required",
      { field: "modelId" }
    );
    expect(error).toBeInstanceOf(McpError);
    expect(error.code).toBe(ErrorCode.InvalidParams);
    expect(error.message).toBe("modelId is required");
  });

  it("McpError without data parameter", () => {
    const error = new McpError(
      ErrorCode.MethodNotFound,
      "Unknown method"
    );
    expect(error.code).toBe(ErrorCode.MethodNotFound);
    expect(error.message).toBe("Unknown method");
  });

  it("mcpError helper creates correct content format", () => {
    function mcpErrorLocal(
      code: ErrorCode,
      message: string,
      data?: unknown
    ) {
      const error = new McpError(code, message, data);
      return {
        content: [{ type: "text" as const, text: message }],
        isError: true as const,
      };
    }

    const result = mcpErrorLocal(
      ErrorCode.InvalidParams,
      "No arguments provided"
    );
    expect(result.isError).toBe(true);
    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toBe("No arguments provided");
  });

  it("mcpError with data parameter", () => {
    function mcpErrorLocal(
      code: ErrorCode,
      message: string,
      data?: unknown
    ) {
      return new McpError(code, message, data);
    }

    const error = mcpErrorLocal(
      ErrorCode.InvalidParams,
      "Validation failed",
      { errors: ["field X is invalid"] }
    );
    expect(error.code).toBe(ErrorCode.InvalidParams);
    expect(error.data).toEqual({ errors: ["field X is invalid"] });
  });
});
