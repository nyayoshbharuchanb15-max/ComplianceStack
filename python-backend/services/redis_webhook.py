# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Redis Streams Webhook Engine — Async Re-Audit Triggers
────────────────────────────────────────────────────────
Enables the "Reaudit Pattern" for continuous compliance monitoring.

When model drift exceeds thresholds, a re-audit event is published
to a Redis Stream. Downstream consumers (or the MCP server) can
subscribe to these events to trigger a new audit cycle.

ISO/IEC 42001:2023 Clause 9.1.2 — Nonconformity detected during
monitoring shall trigger corrective action, which may include a
full or partial re-audit.

Architecture:
  - Drift Detector → publishes to Redis Stream "reaudit:requests"
  - MCP Server (or background worker) → consumes from stream
  - On critical drift → automatic re-audit initiated
"""

from __future__ import annotations
import json
import logging
import os
from typing import Any, Optional
import redis.asyncio as aioredis

logger = logging.getLogger("redis_webhook")


class RedisWebhookEngine:
    """Async Redis Streams client for re-audit event publishing."""

    def __init__(self):
        self.client: Optional[aioredis.Redis] = None

    async def connect(self, url: str = "redis://redis:6379/0") -> None:
        """Initialize Redis connection."""
        self.client = await aioredis.from_url(url, decode_responses=True)

    async def close(self) -> None:
        """Close Redis connection."""
        if self.client:
            await self.client.close()

    async def publish_reaudit_event(
        self,
        model_id: str,
        reason: str,
        triggered_by: str,
        severity: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Publish a re-audit request to the Redis stream.

        Args:
            model_id: Model requiring re-audit
            reason: Why re-audit was triggered (e.g. 'drift_detected')
            triggered_by: Which component triggered it (e.g. 'drift_monitor')
            severity: 'warning' or 'critical'
            metadata: Additional context payload

        Returns:
            Stream entry ID, or None if Redis is unavailable
        """
        if not self.client:
            logger.warning("Redis not available — skipping re-audit event publish")
            return None

        payload = {
            "modelId": model_id,
            "reason": reason,
            "triggeredBy": triggered_by,
            "severity": severity,
            "metadata": json.dumps(metadata or {}),
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }

        try:
            entry_id = await self.client.xadd("reaudit:requests", payload)
            return entry_id
        except Exception:
            logger.exception("Failed to publish re-audit event")
            return None

    async def consume_reaudit_events(
        self,
        group: str = "reaudit-consumers",
        consumer: str = "mcp-worker-1",
        block_ms: int = 5000,
    ) -> list[dict[str, Any]]:
        """
        Consume pending re-audit events from the stream.

        Uses consumer groups for reliable at-least-once delivery.
        """
        if not self.client:
            logger.warning("Redis not available — skipping consume")
            return []

        try:
            await self.client.xgroup_create("reaudit:requests", group, id="0", mkstream=True)
        except aioredis.ResponseError:
            pass

        try:
            messages = await self.client.xreadgroup(
                group, consumer, {"reaudit:requests": ">"}, count=10, block=block_ms
            )

            results = []
            for stream_name, entries in messages:
                for entry_id, fields in entries:
                    results.append({"id": entry_id, "fields": fields})
                    await self.client.xack("reaudit:requests", group, entry_id)

            return results
        except Exception:
            logger.exception("Failed to consume re-audit events")
            return []


webhook_engine = RedisWebhookEngine()
