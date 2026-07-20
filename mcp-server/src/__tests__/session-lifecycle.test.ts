// SPDX-License-Identifier: Apache-2.0
// Regression test for the P1 streamable-http session-lifecycle bug.
//
// Before the fix (index.ts:1052), the express `res.on("close")` handler on
// the initial POST /mcp response terminated the session as soon as the HTTP
// response finished — which meant the *next* request that reused the
// mcp-session-id header would return 404 SESSION_NOT_FOUND. The fix removes
// the premature termination and lets `sessionManager.startCleanup()` (idle
// timeout) or DELETE /mcp handle termination.

import { describe, expect, it } from "vitest";
import express from "express";
import { StreamableHTTPSessionManager } from "../streamable-http-transport.js";
import type { Server } from "node:http";

async function withServer<T>(fn: (base: string) => Promise<T>): Promise<T> {
  const app = express();
  app.use(express.json());
  const sessionManager = new StreamableHTTPSessionManager();

  // Minimal /mcp routes that mirror the wiring in index.ts.
  app.post("/mcp", async (req, res) => {
    const sid = req.headers["mcp-session-id"] as string | undefined;
    if (!sid) {
      const session = sessionManager.createSession();
      res.setHeader("mcp-session-id", session.id);
      // The fix: NO res.on("close") here.
      res.status(200).json({ jsonrpc: "2.0", id: (req.body as { id?: unknown })?.id ?? null, result: { ok: true } });
      return;
    }
    const s = sessionManager.getSession(sid);
    if (!s) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
    res.status(202).json({ ok: true });
  });
  app.delete("/mcp", async (req, res) => {
    const sid = req.headers["mcp-session-id"] as string | undefined;
    if (sid) await sessionManager.terminateSession(sid);
    res.status(200).json({ ok: true });
  });

  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

describe("streamable-http session lifecycle (P1 regression)", () => {
  it("preserves the session across the initial POST close", async () => {
    await withServer(async (base) => {
      const r1 = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      });
      const sid = r1.headers.get("mcp-session-id");
      expect(sid).toBeTruthy();
      // A follow-up POST reusing the same session-id must NOT return 404.
      const r2 = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "mcp-session-id": sid!,
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
      expect(r2.status).toBe(202); // session found
    });
  });

  it("terminates the session on explicit DELETE /mcp", async () => {
    await withServer(async (base) => {
      const r1 = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      });
      const sid = r1.headers.get("mcp-session-id")!;

      const del = await fetch(`${base}/mcp`, {
        method: "DELETE",
        headers: { "mcp-session-id": sid },
      });
      expect(del.status).toBe(200);

      // Next POST with a terminated session id → 404
      const r2 = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "mcp-session-id": sid,
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
      expect(r2.status).toBe(404);
    });
  });

  it("SSE detach does not terminate the session (detachSSE only clears the ref)", async () => {
    // Direct unit-test of detachSSE — a follow-up POST after SSE close must
    // still work because the session lives in the session manager.
    const { StreamableHTTPTransport } = await import("../streamable-http-transport.js");
    const t = new StreamableHTTPTransport("sess-1");
    const fakeRes = { writableEnded: false, write: () => {}, end: () => {} } as unknown as import("express").Response;
    t.attachSSE(fakeRes);
    // Simulate SSE close via detachSSE.
    t.detachSSE(fakeRes);
    // A new send() after detach must NOT throw and must queue.
    await expect(t.send({ jsonrpc: "2.0", method: "ping" } as unknown as import("@modelcontextprotocol/sdk/types.js").JSONRPCMessage)).resolves.toBeUndefined();
  });
});
