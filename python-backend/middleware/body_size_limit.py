# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Body Size Limit Middleware — Input Validation
──────────────────────────────────────────────
Rejects requests with bodies exceeding a configurable maximum size.

Protects against:
  - Resource exhaustion (large payloads)
  - DoS via oversized request bodies
  - Accidental large uploads

Default limit: 10 MB (configurable via MAX_BODY_SIZE env var, in bytes).
"""

from __future__ import annotations
import os
import logging
from typing import Any
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse

logger = logging.getLogger("body_size_limit")

DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = DEFAULT_MAX_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == "/health":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        # Check Content-Length header first (fast path — avoids buffering)
        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                content_length = int(value)
                if content_length > self.max_bytes:
                    request_id = scope.get("request_id", "")
                    resp = JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "detail": f"Request body exceeds maximum allowed size of {self.max_bytes} bytes.",
                            "max_bytes": self.max_bytes,
                        },
                        headers={"X-Request-ID": request_id} if request_id else {},
                    )
                    await resp(scope, receive, send)
                    return
                break

        # Buffer all body chunks to measure actual size (for chunked encoding)
        total = 0
        chunks: list[bytes] = []
        more_body = True

        while more_body:
            msg = await receive()
            if msg["type"] == "http.request":
                chunk = msg.get("body", b"")
                chunks.append(chunk)
                total += len(chunk)
                if total > self.max_bytes:
                    request_id = scope.get("request_id", "")
                    logger.warning(
                        "Request body exceeded %d bytes (path=%s, method=%s, total=%d)",
                        self.max_bytes, path, method, total,
                    )
                    resp = JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "detail": f"Request body exceeds maximum allowed size of {self.max_bytes} bytes.",
                            "max_bytes": self.max_bytes,
                        },
                        headers={"X-Request-ID": request_id} if request_id else {},
                    )
                    await resp(scope, receive, send)
                    return
                more_body = msg.get("more_body", False)
            else:
                break

        # Replay the buffered body to the rest of the ASGI stack
        chunks_iter = iter(chunks)
        num_chunks = len(chunks)
        chunk_index = 0

        async def replayed_receive() -> dict[str, Any]:
            nonlocal chunk_index
            try:
                chunk = next(chunks_iter)
                is_last = (chunk_index + 1) >= num_chunks
                chunk_index += 1
                return {
                    "type": "http.request",
                    "body": chunk,
                    "more_body": not is_last,
                }
            except StopIteration:
                return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replayed_receive, send)
