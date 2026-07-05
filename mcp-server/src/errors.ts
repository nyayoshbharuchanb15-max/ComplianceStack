// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nyayosh Bharuchanb15-Max

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

export const ERROR_CODE_REQUEST_CANCELLED = -32800;
