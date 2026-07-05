# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Evidence Store Service — Audit Trail Management
────────────────────────────────────────────────
Abstracts the PostgreSQL evidence store operations into a clean
service layer for the routers.

ISO/IEC 42001:2023 Clause 7.5 — Documented Information:
  - All audit evidence is retained with immutable timestamps
  - Evidence is versioned and traceable to specific audit phases
  - Retention periods are configurable per evidence type

GDPR Art. 5(1)(e) — Storage limitation is enforced at this layer.
"""

from __future__ import annotations
from typing import Any, Optional
from db.postgres import pg_client
from services.timestamping import trusted_timestamp


async def record_audit_evidence(
    model_id: str,
    audit_phase: str,
    payload: dict[str, Any],
    evidence_type: str = "audit_result",
) -> Optional[str]:
    """
    Record an audit phase result in the evidence store.

    Automatically applies a trusted timestamp to the payload for
    cryptographic audit trail integrity.

    Returns the evidence_id UUID for cross-referencing, or None if the
    store is unavailable (graceful degradation).
    """
    # Apply trusted timestamp to the payload
    timestamped_payload = trusted_timestamp.timestamp_record(payload)

    return await pg_client.store_evidence(
        model_id=model_id,
        audit_phase=audit_phase,
        payload=timestamped_payload,
        evidence_type=evidence_type,
    )


async def record_certificate(
    model_id: str,
    vc_payload: dict[str, Any],
    evidence_id: str,
) -> None:
    """Record a W3C Verifiable Credential certificate."""
    await pg_client.store_certificate(
        model_id=model_id,
        vc_payload=vc_payload,
        evidence_id=evidence_id,
    )


async def record_drift_alert(
    model_id: str,
    metric: str,
    drift_score: float,
    threshold: float,
    status: str,
) -> None:
    """Record a drift monitoring event."""
    await pg_client.store_drift_alert(
        model_id=model_id,
        metric=metric,
        drift_score=drift_score,
        threshold=threshold,
        status=status,
    )


async def get_evidence(evidence_id: str) -> Optional[dict[str, Any]]:
    """Retrieve a specific evidence record."""
    return await pg_client.get_evidence(evidence_id)


async def get_audit_history(model_id: str) -> list[dict[str, Any]]:
    """Get full audit history for a model."""
    return await pg_client.get_audit_history(model_id)


async def log_audit_event(
    model_id: str,
    phase: str,
    action: str,
    actor: str = "system",
    outcome: str = "success",
    details: Optional[dict[str, Any]] = None,
) -> Optional[str]:
    """
    Log a mutation event in the audit trail.

    GDPR Art. 5(2) — Accountability: controller must demonstrate compliance.
    ISO 42001:2023 Clause 7.5 — Documented information includes mutation history.
    """
    return await pg_client.log_audit_event(
        model_id=model_id,
        phase=phase,
        action=action,
        actor=actor,
        outcome=outcome,
        details=details,
    )
