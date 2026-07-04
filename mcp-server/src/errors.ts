import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";

export class McpError extends Error {
  code: ErrorCode;
  data?: unknown;

  constructor(code: ErrorCode, message: string, data?: unknown) {
    super(message);
    this.name = "McpError";
    this.code = code;
    this.data = data;
  }
}
