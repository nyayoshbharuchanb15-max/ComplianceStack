// SPDX-License-Identifier: Apache-2.0
// ─── Governance Orchestrator HTTP Client ─────────────────────────
// Policy-gated client for the FastAPI orchestration engine.
// Enforces LEAST PRIVILEGE at the MCP layer: the service-account JWT's
// scopes are checked BEFORE any request reaches FastAPI. Also computes
// X-Request-Hash (SHA-256 over the canonical JSON body) so the
// orchestrator can verify request integrity.

import crypto from "node:crypto";

const GOVERNANCE_API_URL = process.env.GOVERNANCE_API_URL || "http://localhost:8001";
const CLIENT_ID = process.env.GOVERNANCE_CLIENT_ID || "governance-admin";
const CLIENT_SECRET = process.env.GOVERNANCE_CLIENT_SECRET || "";

let cachedToken: string | null = process.env.GOVERNANCE_TOKEN || null;

export class GovernanceAuthzError extends Error {}
export class GovernanceValidationError extends Error {}

// Canonical JSON — must match store/hashing.py canonical_json (sorted keys, compact).
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map((v) => canonicalJson(v ?? null)).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    return JSON.parse(Buffer.from(part, "base64url").toString("utf-8"));
  } catch {
    return null;
  }
}

function tokenIsUsable(token: string | null): boolean {
  if (!token) return false;
  const payload = decodeJwtPayload(token);
  if (!payload) return false;
  const exp = payload.exp as number | undefined;
  return exp === undefined || exp * 1000 > Date.now() + 30_000;
}

async function fetchToken(): Promise<string> {
  const resp = await fetch(`${GOVERNANCE_API_URL}/api/v1/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET }),
  });
  if (!resp.ok) {
    throw new Error(`Governance token issuance failed (${resp.status}): ${await resp.text()}`);
  }
  const data = (await resp.json()) as { accessToken: string };
  return data.accessToken;
}

async function getToken(): Promise<string> {
  if (!tokenIsUsable(cachedToken)) {
    cachedToken = await fetchToken();
  }
  return cachedToken as string;
}

// TypeScript-layer authorization gate (before FastAPI is invoked).
export function assertScope(token: string, requiredScope: string): void {
  const payload = decodeJwtPayload(token);
  const scopes = (payload?.scopes as string[]) || [];
  if (!scopes.includes(requiredScope)) {
    throw new GovernanceAuthzError(
      `Authorization rejected at MCP layer: role '${payload?.role ?? "unknown"}' lacks ` +
      `required scope '${requiredScope}'. Request was NOT forwarded to the orchestrator.`,
    );
  }
}

export async function callGovernance<T>(
  path: string,
  requiredScope: string,
  body?: unknown,
  method: "POST" | "GET" = "POST",
  timeout = 60_000,
): Promise<T> {
  const token = await getToken();
  assertScope(token, requiredScope);

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    "X-Request-ID": crypto.randomUUID(),
  };
  let payload: string | undefined;
  if (method === "POST") {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body ?? {});
    headers["X-Request-Hash"] = crypto
      .createHash("sha256")
      .update(canonicalJson(body ?? {}), "utf-8")
      .digest("hex");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(`${GOVERNANCE_API_URL}${path}`, {
      method,
      headers,
      body: payload,
      signal: controller.signal,
    });
    const text = await resp.text();
    if (!resp.ok) {
      let detail = text;
      try {
        const parsed = JSON.parse(text);
        detail = typeof parsed.detail === "object" ? JSON.stringify(parsed.detail) : String(parsed.detail ?? text);
      } catch {
        /* raw text */
      }
      throw new Error(`Orchestrator error (${resp.status}): ${detail}`);
    }
    return JSON.parse(text) as T;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`Request to ${path} timed out after ${timeout}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
