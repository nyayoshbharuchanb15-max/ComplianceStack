# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
PII Redaction Middleware — Zero-Trust Data Minimization
─────────────────────────────────────────────────────────
Intercepts all /api/* request and response bodies, redacting PII
via the existing PIIRedactor singleton.

  - Requests:  PII is detected, redacted before forwarding, and logged (field names only)
  - Responses: PII is redacted before leaving the server
  - Header:    X-PII-Redacted: true when any field was redacted
  - Audit:     Each event is recorded in the pii_redactions table

GDPR Art. 5(1)(c) — Data minimisation.
GDPR Art. 5(2)   — Accountability (demonstrate compliance).
GDPR Art. 25     — Data protection by design and by default.
DPDP Act 2023 Sec. 8(4) — Safeguards including anonymization.
"""

from __future__ import annotations
import json
import logging
from typing import Any, Optional

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

from db.postgres import pg_client
from services.pii_redactor import pii_redactor

logger = logging.getLogger("pii_middleware")

SKIP_PREFIXES = ("/health", "/api/auth/")
JSON_CONTENT_TYPES = ("application/json", "application/problem+json")


class PIIRedactionMiddleware:
    """
    ASGI middleware that redacts PII from both request and response bodies.

    - Request body: PII is detected, logged (field names only), and redacted
      before the route handler receives it. This enforces GDPR Art. 5(1)(c)
      data minimization at the API boundary.
    - Response body: PII is detected, logged, and redacted before leaving
      the server.
    - X-PII-Redacted: true header is injected when any PII was removed.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(p) for p in SKIP_PREFIXES):
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        endpoint = f"{method} {path}"

        # ── Request interception ───────────────────────────────
        # Read raw body, detect PII, redact, and forward the redacted version.
        body_received: list[bytes] = []
        request_pii_fields: list[str] = []
        redacted_request_body: Optional[bytes] = None

        async def receive_wrapper():
            nonlocal body_received, request_pii_fields, redacted_request_body
            msg = await receive()
            if msg["type"] == "http.request":
                chunk = msg.get("body", b"")
                body_received.append(chunk)
                if msg.get("more_body", False) is False and chunk:
                    try:
                        full_body = b"".join(body_received)
                        data = json.loads(full_body)
                        redacted = pii_redactor.redact(data)
                        request_pii_fields = _find_redacted_field_paths(data, redacted)
                        if request_pii_fields:
                            redacted_request_body = json.dumps(
                                redacted, default=str
                            ).encode("utf-8")
                            # Return redacted body to the route handler
                            msg = {**msg, "body": redacted_request_body}
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
            return msg

        # ── Response interception ──────────────────────────────
        response_body: list[bytes] = []
        response_pii_fields: list[str] = []
        response_status = 500
        response_headers: Optional[MutableHeaders] = None

        async def send_wrapper(msg: dict[str, Any]) -> None:
            nonlocal response_body, response_pii_fields, response_status, response_headers
            if msg["type"] == "http.response.start":
                response_status = msg.get("status", 500)
                response_headers = MutableHeaders(raw=msg.get("headers", []))
                await send(msg)
            elif msg["type"] == "http.response.body":
                chunk = msg.get("body", b"")
                response_body.append(chunk)
                if msg.get("more_body", False) is False:
                    full_body = b"".join(response_body)
                    content_type = (response_headers or {}).get("Content-Type", "") if response_headers else ""
                    if any(ct in content_type for ct in JSON_CONTENT_TYPES) and full_body:
                        try:
                            data = json.loads(full_body)
                            redacted = pii_redactor.redact(data)
                            response_pii_fields = _find_redacted_field_paths(data, redacted)
                            redacted_bytes = json.dumps(redacted, default=str).encode("utf-8")
                            if response_headers is not None:
                                response_headers["Content-Length"] = str(len(redacted_bytes))
                                if response_pii_fields:
                                    response_headers["X-PII-Redacted"] = "true"
                            await send({
                                "type": "http.response.body",
                                "body": redacted_bytes,
                                "more_body": False,
                            })
                            return
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            pass
                await send(msg)

        # ── Run request through the rest of the stack ──────────
        await self.app(scope, receive_wrapper, send_wrapper)

        # ── Post-request: log redaction events ─────────────────
        all_redacted = list(dict.fromkeys(request_pii_fields + response_pii_fields))
        if all_redacted:
            try:
                await pg_client.store_pii_redaction_event(
                    endpoint=endpoint,
                    redacted_fields=all_redacted,
                    request_path=path,
                )
            except Exception:
                logger.warning("Failed to log PII redaction event", exc_info=True)


def _find_redacted_field_paths(
    original: Any,
    redacted: Any,
    prefix: str = "",
) -> list[str]:
    """
    Recursively identify field paths where values differ between
    original and redacted data (indicating PII was removed).

    Returns a flat list of dotted field paths.
    """
    fields: list[str] = []
    _walk(original, redacted, prefix, fields)
    return fields


def _walk(
    original: Any,
    redacted: Any,
    prefix: str,
    fields: list[str],
) -> None:
    if type(original) is not type(redacted):
        if prefix:
            fields.append(prefix)
        return

    if isinstance(original, dict) and isinstance(redacted, dict):
        all_keys = set(original) | set(redacted)
        for key in sorted(all_keys):
            new_prefix = f"{prefix}.{key}" if prefix else key
            if key not in redacted:
                fields.append(new_prefix)
            elif key not in original:
                pass
            else:
                if original[key] != redacted[key]:
                    _walk(original[key], redacted[key], new_prefix, fields)

    elif isinstance(original, list) and isinstance(redacted, list):
        for i in range(min(len(original), len(redacted))):
            new_prefix = f"{prefix}[{i}]"
            if original[i] != redacted[i]:
                _walk(original[i], redacted[i], new_prefix, fields)
        if len(original) != len(redacted):
            fields.append(prefix)

    elif original != redacted:
        if prefix:
            fields.append(prefix)
