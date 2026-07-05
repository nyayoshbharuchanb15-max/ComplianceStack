# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Request ID Tracing Middleware — Distributed Tracing Support
────────────────────────────────────────────────────────────
Propagates X-Request-ID headers through the request lifecycle:
  - If the client sends an X-Request-ID, it is preserved
  - If no X-Request-ID is present, a UUID is generated
  - The ID is attached to scope["request_id"]
  - The response includes the X-Request-ID header
"""

from __future__ import annotations
import uuid
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.datastructures import MutableHeaders


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])
        request_id = None
        for name, value in headers:
            if name.lower() == b"x-request-id":
                request_id = value.decode()
                break
        if request_id is None:
            request_id = uuid.uuid4().hex
            headers = list(headers)
            headers.append((b"x-request-id", request_id.encode()))
            scope["headers"] = headers

        scope["request_id"] = request_id

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                msg_headers = MutableHeaders(raw=message.get("headers", []))
                msg_headers["X-Request-ID"] = request_id
            await send(message)

        await self.app(scope, receive, send_wrapper)
