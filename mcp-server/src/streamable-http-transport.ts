// ═══════════════════════════════════════════════════════════════════
//  Streamable HTTP Transport — MCP Protocol Implementation
//  Implements the MCP Streamable HTTP transport specification:
//    POST /mcp   — JSON-RPC messages (application/json or x-ndjson)
//    GET  /mcp   — SSE stream for server-initiated messages
//    DELETE /mcp — Session termination
//
//  Each HTTP request creates or routes to a Transport instance.
//  The Transport implements the MCP SDK Transport interface so it
//  can be used with Server.connect().
// ═══════════════════════════════════════════════════════════════════

import { randomUUID } from "node:crypto";
import type { Express, Request, Response } from "express";

// ─── MCP JSON-RPC Types ─────────────────────────────────────────

interface JSONRPCRequest {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

interface JSONRPCResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface JSONRPCNotification {
  jsonrpc: "2.0";
  method: string;
  params?: Record<string, unknown>;
}

type JSONRPCMessage = JSONRPCRequest | JSONRPCResponse | JSONRPCNotification;

// ─── Transport Interface (matches MCP SDK) ──────────────────────

export interface Transport {
  start(): Promise<void>;
  send(message: JSONRPCMessage): Promise<void>;
  close(): Promise<void>;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
}

// ─── Session State ──────────────────────────────────────────────

interface SessionState {
  id: string;
  transport: StreamableHTTPTransport;
  sseRes?: Response;
  createdAt: number;
  lastActivity: number;
}

// ─── StreamableHTTPTransport ────────────────────────────────────

export class StreamableHTTPTransport implements Transport {
  private _started = false;
  private _closed = false;
  private _pendingMessages: JSONRPCMessage[] = [];
  private _sseRes?: Response;
  private _sessionId: string;

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor(sessionId: string) {
    this._sessionId = sessionId;
  }

  get sessionId(): string {
    return this._sessionId;
  }

  async start(): Promise<void> {
    this._started = true;
    // Flush any messages queued before start
    const queued = this._pendingMessages;
    this._pendingMessages = [];
    for (const msg of queued) {
      await this.send(msg);
    }
  }

  async send(message: JSONRPCMessage): Promise<void> {
    if (this._closed) return;

    // If SSE connection is active, push via SSE
    if (this._sseRes && !this._sseRes.writableEnded) {
      const data = JSON.stringify(message);
      this._sseRes.write(`data: ${data}\n\n`);
      return;
    }

    // Otherwise queue for when SSE connects or for direct response
    this._pendingMessages.push(message);
  }

  async close(): Promise<void> {
    this._closed = true;
    if (this._sseRes && !this._sseRes.writableEnded) {
      this._sseRes.write(`event: close\ndata: {}\n\n`);
      this._sseRes.end();
    }
    this.onclose?.();
  }

  /**
   * Handle an incoming HTTP POST with a JSON-RPC message.
   * Called by the Express route handler.
   */
  async handlePostMessage(req: Request, res: Response): Promise<void> {
    if (this._closed) {
      res.status(410).json({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Session terminated" },
        id: null,
      });
      return;
    }

    const contentType = req.headers["content-type"] || "";

    // Handle application/json (single message or batch)
    if (contentType.includes("application/json")) {
      const body = req.body;

      if (Array.isArray(body)) {
        // Batch request
        const responses: JSONRPCResponse[] = [];
        for (const msg of body) {
          if (msg.method && msg.id !== undefined) {
            // Request — process and collect response
            const response = await this._processRequest(msg);
            if (response) responses.push(response);
          } else if (msg.method && msg.id === undefined) {
            // Notification — forward to handler
            this.onmessage?.(msg);
          }
        }
        if (responses.length > 0) {
          res.json(responses.length === 1 ? responses[0] : responses);
        } else {
          res.status(202).json({ accepted: true });
        }
      } else if (body.method && body.id !== undefined) {
        // Single request
        const response = await this._processRequest(body);
        if (response) {
          res.json(response);
        } else {
          res.status(202).json({ accepted: true });
        }
      } else if (body.method) {
        // Notification
        this.onmessage?.(body);
        res.status(202).json({ accepted: true });
      } else {
        res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32600, message: "Invalid JSON-RPC message" },
          id: null,
        });
      }
      return;
    }

    // Handle application/x-ndjson (newline-delimited)
    if (contentType.includes("application/x-ndjson")) {
      const raw = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
      const lines = raw.split("\n").filter((l: string) => l.trim());
      const responses: JSONRPCResponse[] = [];

      for (const line of lines) {
        try {
          const msg = JSON.parse(line);
          if (msg.method && msg.id !== undefined) {
            const response = await this._processRequest(msg);
            if (response) responses.push(response);
          } else if (msg.method) {
            this.onmessage?.(msg);
          }
        } catch {
          // Skip malformed lines
        }
      }

      if (responses.length > 0) {
        res.setHeader("Content-Type", "application/x-ndjson");
        res.send(responses.map((r) => JSON.stringify(r)).join("\n") + "\n");
      } else {
        res.status(202).json({ accepted: true });
      }
      return;
    }

    res.status(415).json({
      jsonrpc: "2.0",
      error: {
        code: -32600,
        message: "Unsupported Content-Type. Use application/json or application/x-ndjson",
      },
      id: null,
    });
  }

  /**
   * Attach an SSE response for server-initiated messages.
   * Called by the GET /mcp route handler.
   */
  attachSSE(res: Response): void {
    this._sseRes = res;

    // Flush any queued messages
    while (this._pendingMessages.length > 0) {
      const msg = this._pendingMessages.shift()!;
      const data = JSON.stringify(msg);
      res.write(`data: ${data}\n\n`);
    }
  }

  /**
   * Process a single JSON-RPC request and return a response.
   * If the handler returns undefined (e.g., for notifications), return null.
   */
  private async _processRequest(
    msg: JSONRPCRequest
  ): Promise<JSONRPCResponse | null> {
    return new Promise((resolve) => {
      const responsePromise = new Promise<JSONRPCResponse | void>((res) => {
        // Set up one-time message handler for the response
        const originalOnMessage = this.onmessage;
        this.onmessage = (response) => {
          this.onmessage = originalOnMessage;
          if ("id" in response && (response as JSONRPCResponse).id === msg.id) {
            res(response as JSONRPCResponse);
          } else {
            // It's a notification or different response — forward
            originalOnMessage?.(response);
          }
        };

        // Forward the request to the MCP server
        this.onmessage?.(msg);

        // Timeout after 30 seconds
        setTimeout(() => {
          resolve({
            jsonrpc: "2.0",
            id: msg.id,
            error: { code: -32603, message: "Request timed out" },
          });
        }, 30000);
      });

      responsePromise.then(resolve);
    });
  }
}

// ─── Session Manager ────────────────────────────────────────────

export class StreamableHTTPSessionManager {
  private _sessions: Map<string, SessionState> = new Map();
  private _sessionTimeout: number;
  private _cleanupInterval: NodeJS.Timeout | null = null;

  constructor(sessionTimeoutMs: number = 3600000) {
    this._sessionTimeout = sessionTimeoutMs;
  }

  /**
   * Create a new session with a fresh transport.
   */
  createSession(): SessionState {
    const id = randomUUID();
    const transport = new StreamableHTTPTransport(id);
    const session: SessionState = {
      id,
      transport,
      createdAt: Date.now(),
      lastActivity: Date.now(),
    };
    this._sessions.set(id, session);
    return session;
  }

  /**
   * Get an existing session by ID.
   */
  getSession(id: string): SessionState | undefined {
    const session = this._sessions.get(id);
    if (session) {
      session.lastActivity = Date.now();
    }
    return session;
  }

  /**
   * Terminate a session and clean up its SSE connection.
   */
  async terminateSession(id: string): Promise<boolean> {
    const session = this._sessions.get(id);
    if (!session) return false;

    await session.transport.close();
    this._sessions.delete(id);
    return true;
  }

  /**
   * Get the number of active sessions.
   */
  get sessionCount(): number {
    return this._sessions.size;
  }

  /**
   * Start periodic cleanup of expired sessions.
   */
  startCleanup(): void {
    const checkInterval = Math.min(this._sessionTimeout, 60000);
    this._cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [id, session] of this._sessions) {
        if (now - session.lastActivity > this._sessionTimeout) {
          session.transport.close();
          this._sessions.delete(id);
        }
      }
    }, checkInterval);
  }

  /**
   * Stop cleanup interval.
   */
  stopCleanup(): void {
    if (this._cleanupInterval) {
      clearInterval(this._cleanupInterval);
      this._cleanupInterval = null;
    }
  }
}
