# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Rate Limiting Middleware — Redis Sliding Window
────────────────────────────────────────────────
Implements a sliding window rate limiter backed by Redis.

Per-route tiers (configurable via env vars):
  - /api/auth/*: 20 req/min (login/register)
  - /api/* POST: 60 req/min (audit operations)
  - /api/* GET:  120 req/min (read operations)
  - /health:     unlimited

When Redis is unavailable, requests pass through (graceful degradation).

Returns 429 Too Many Requests with Retry-After header when exceeded.

NIST AI RMF GOVERN 1.5 — Rate limiting prevents abuse.
"""

from __future__ import annotations
import os
import time
import logging
from typing import Optional
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse

from services.redis_webhook import webhook_engine

logger = logging.getLogger("rate_limit")

RATE_TIERS: dict[str, tuple[int, int]] = {
    "auth": (60, int(os.environ.get("RATE_LIMIT_AUTH", "20"))),
    "write": (60, int(os.environ.get("RATE_LIMIT_WRITE", "60"))),
    "read": (60, int(os.environ.get("RATE_LIMIT_READ", "120"))),
}

SKIP_PATHS = ("/health",)


def _get_tier(path: str, method: str) -> Optional[tuple[int, int]]:
    if any(path.startswith(p) for p in SKIP_PATHS):
        return None
    if path.startswith("/api/auth/"):
        return RATE_TIERS["auth"]
    if method in ("GET", "HEAD", "OPTIONS"):
        return RATE_TIERS["read"]
    return RATE_TIERS["write"]


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")
        client_host = scope.get("client", ("127.0.0.1", 0))[0]
        request_id = scope.get("request_id", "")

        tier = _get_tier(path, method)
        if tier is None:
            await self.app(scope, receive, send)
            return

        window, max_reqs = tier
        key = f"ratelimit:{client_host}:{method}:{path}"

        redis = webhook_engine.client
        if redis is not None:
            try:
                now = int(time.time())
                window_start = now - window
                await redis.zremrangebyscore(key, 0, window_start)
                count = await redis.zcard(key)
                if count >= max_reqs:
                    oldest = await redis.zrange(key, 0, 0, withscores=True)
                    retry_after = int(window - (now - (oldest[0][1] if oldest else 0))) + 1
                    resp = JSONResponse(
                        status_code=429,
                        content={
                            "error": "rate_limit_exceeded",
                            "detail": f"Rate limit exceeded. Try again in {retry_after}s.",
                            "retry_after": retry_after,
                        },
                        headers={
                            "Retry-After": str(retry_after),
                            "X-Request-ID": request_id,
                        },
                    )
                    await resp(scope, receive, send)
                    return
                await redis.zadd(key, {str(now): now})
                await redis.expire(key, window)
            except Exception:
                logger.warning("Rate limiter backend error", exc_info=True)

        await self.app(scope, receive, send)
