// ═══════════════════════════════════════════════════════════════════
//  Tool Input Validator — MCP-Layer JSON Schema Validation
//  Uses ajv to validate all tool parameters against their JSON Schema
//  before forwarding to the Python backend. Rejects malformed inputs
//  at the MCP protocol level with structured error responses.
//
//  IMPORTANT: This file imports from tool-schemas.ts (single source
//  of truth). NO manual sync needed — schemas are shared with index.ts.
// ═══════════════════════════════════════════════════════════════════

import Ajv, { type ValidateFunction, type ErrorObject } from "ajv";
import { TOOL_SCHEMAS } from "./tool-schemas.js";

const ajv = new Ajv({
  allErrors: true,
  strict: false,
  removeAdditional: false,
});

// ─── Compiled Validators ────────────────────────────────────────

const validators: Map<string, ValidateFunction> = new Map();

for (const tool of TOOL_SCHEMAS) {
  validators.set(tool.name, ajv.compile(tool.inputSchema));
}

// ─── Validation Result ──────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  errors?: ErrorObject[];
}

// ─── Public API ─────────────────────────────────────────────────

/**
 * Validate tool arguments against the tool's JSON Schema.
 * Returns { valid: true } or { valid: false, errors: [...] }.
 */
export function validateToolInput(
  toolName: string,
  args: Record<string, unknown>
): ValidationResult {
  const validate = validators.get(toolName);
  if (!validate) {
    return { valid: false, errors: [{ instancePath: "", schemaPath: "#", keyword: "unknown", params: {}, message: `Unknown tool: ${toolName}` }] };
  }

  const valid = validate(args);
  if (valid) {
    return { valid: true };
  }

  return { valid: false, errors: validate.errors || [] };
}

/**
 * Get the list of all registered tool names.
 */
export function getRegisteredTools(): string[] {
  return TOOL_SCHEMAS.map((t) => t.name);
}

/**
 * Get the schema for a specific tool.
 */
export function getToolSchema(toolName: string): Record<string, unknown> | undefined {
  const tool = TOOL_SCHEMAS.find((t) => t.name === toolName);
  return tool?.inputSchema;
}
