// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nyayosh Bharuchanb15-Max

// ─── Python Backend HTTP Client ──────────────────────────────────
// Forwards all audit requests from the MCP server to the Python FastAPI
// microservices. Supports authentication via Bearer tokens.
//
// Security: The MCP server authenticates with the Python backend using
// a service account token. Individual user context (role, scopes) is
// forwarded via X-MCP-User-* headers for per-user RBAC enforcement.

const PYTHON_BACKEND_URL = process.env.PYTHON_BACKEND_URL || "http://localhost:8000";
const AUTH_TOKEN = process.env.AUTH_TOKEN || "";

interface FetchOptions {
  method?: string;
  body?: unknown;
  timeout?: number;
  userContext?: {
    userId: string;
    role: string;
    scopes: string[];
  };
}

export async function callPythonBackend<T>(
  path: string,
  opts: FetchOptions = {},
): Promise<T> {
  const { method = "POST", body, timeout = 60000, userContext } = opts;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Attach Bearer token if available (OAuth 2.1)
  if (AUTH_TOKEN) {
    headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
  }

  // Attach request ID for audit trail correlation
  headers["X-Request-ID"] = crypto.randomUUID();

  // Forward per-user context for RBAC enforcement at the backend
  if (userContext) {
    headers["X-MCP-User-ID"] = userContext.userId;
    headers["X-MCP-User-Role"] = userContext.role;
    headers["X-MCP-User-Scopes"] = userContext.scopes.join(",");
  }

  try {
    const response = await fetch(`${PYTHON_BACKEND_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    if (response.status === 401) {
      throw new Error(
        "Authentication failed (401). Ensure AUTH_TOKEN is set correctly "
        + "or the service account has valid credentials."
      );
    }

    if (response.status === 403) {
      throw new Error(
        "Authorization failed (403). The service account lacks the required "
        + "scope for this operation."
      );
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Python backend error (${response.status}): ${errorText}`);
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`Request to ${path} timed out after ${timeout}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
