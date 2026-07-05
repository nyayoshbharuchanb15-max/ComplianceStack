# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Session Memory Auditor — STM/LTM Isolation Verification
──────────────────────────────────────────────────────────
Evaluates short-term memory isolation, context window limits,
session data wipe-on-expiry, and cross-session data leakage prevention.

GDPR Art. 5(1)(f) — Integrity and confidentiality.
GDPR Art. 25 — Data protection by design.
DPDP Act 2023 Sec. 8 — Processor duties.
EU AI Act Art. 15 — Accuracy and monitoring.
ISO/IEC 42001:2023 Clause 8.2 — Memory isolation controls.
"""

from __future__ import annotations
from typing import Any, Optional
from models.schemas import (
    SessionMemorySection,
    SessionMemoryReport,
    RiskLevel,
)


async def audit_session_memory(
    model_id: str,
    session_id: str,
    stm_config: dict[str, Any],
    ltm_config: Optional[dict[str, Any]],
    session_timeout_minutes: int,
    isolation_level: str,
) -> SessionMemoryReport:
    """Run full session memory audit across 10 compliance sections."""
    sections = _evaluate_sections(stm_config, ltm_config, session_timeout_minutes, isolation_level)

    compliant_count = sum(1 for s in sections if s.status == "compliant")
    total = max(len(sections), 1)
    ratio = compliant_count / total

    isolation_score = _compute_isolation_score(sections)
    memory_retention_ok = all(
        s.status == "compliant" for s in sections
        if "Retention" in s.section or "Wipe" in s.section
    )
    wipe_verified = any(
        s.status == "compliant" and "Wipe" in s.section
        for s in sections
    )

    overall_risk = _derive_risk(ratio, isolation_score)

    return SessionMemoryReport(
        modelId=model_id,
        sessionId=session_id,
        sections=sections,
        contextIsolationScore=isolation_score,
        memoryRetentionCompliant=memory_retention_ok,
        wipeOnExpiryVerified=wipe_verified,
        overallRisk=overall_risk,
        compliant=ratio >= 0.7 and isolation_score >= 0.6,
    )


def _evaluate_sections(
    stm_config: dict[str, Any],
    ltm_config: Optional[dict[str, Any]],
    timeout_minutes: int,
    isolation_level: str,
) -> list[SessionMemorySection]:
    """Evaluate 10 memory compliance sections."""
    sections = []

    # 1. Session Isolation
    is_isolated = isolation_level in ("per_user", "per_session")
    sections.append(SessionMemorySection(
        section="Session Isolation",
        requirement="STM must be isolated per user or per session, with no cross-contamination between concurrent sessions.",
        status="compliant" if is_isolated else "non_compliant",
        finding=(
            f"Isolation level is '{isolation_level}'. "
            + ("Sessions are properly isolated." if is_isolated else "Shared session memory allows cross-contamination.")
        ),
        remediation="Configure STM isolation to per_user or per_session mode.",
    ))

    # 2. Context Window Limits
    max_tokens = stm_config.get("maxTokens", stm_config.get("max_tokens", 0))
    has_limit = isinstance(max_tokens, int) and max_tokens > 0
    sections.append(SessionMemorySection(
        section="Context Window Limits",
        requirement="Active context must not exceed model context window limits; truncation must be safe and predictable.",
        status="compliant" if has_limit else "partially_compliant",
        finding=(
            f"maxTokens is set to {max_tokens}. "
            + ("Context window limit is configured." if has_limit else "No explicit context window limit found.")
        ),
        remediation="Set maxTokens in STM config to a value within the model's context window.",
    ))

    # 3. Working Memory Wipe
    wipe_on_expire = stm_config.get("wipeOnExpiry", stm_config.get("wipe_on_expiry", False))
    sections.append(SessionMemorySection(
        section="Working Memory Wipe",
        requirement="Session buffer must be cleared on timeout or logout to prevent data persistence.",
        status="compliant" if wipe_on_expire else "non_compliant",
        finding=(
            "Wipe-on-expiry is enabled." if wipe_on_expire
            else "Session data may persist after timeout — risk of stale data exposure."
        ),
        remediation="Enable wipeOnExpiry in STM config to clear session buffer on timeout.",
    ))

    # 4. Session Buffer Overflow
    max_history = stm_config.get("maxHistory", stm_config.get("max_history", 0))
    has_buffer_limit = isinstance(max_history, int) and max_history > 0
    sections.append(SessionMemorySection(
        section="Session Buffer Overflow",
        requirement="Chat history buffer must have bounded growth to prevent memory exhaustion.",
        status="compliant" if has_buffer_limit else "partially_compliant",
        finding=(
            f"maxHistory is set to {max_history}. " if has_buffer_limit
            else "No history limit configured — unbounded growth possible."
        ),
        remediation="Set maxHistory to bound the session buffer size.",
    ))

    # 5. LTM Access Control
    has_ltm = ltm_config is not None and len(ltm_config) > 0
    ltm_restricted = has_ltm and ltm_config.get("accessControl", ltm_config.get("access_control", "")) != ""
    sections.append(SessionMemorySection(
        section="LTM Access Control",
        requirement="Long-term memory retrieval must respect user boundaries and tenant isolation.",
        status="compliant" if ltm_restricted else ("partially_compliant" if has_ltm else "non_compliant"),
        finding=(
            "LTM access control is configured." if ltm_restricted
            else ("LTM present but no access control defined." if has_ltm else "No LTM configuration provided.")
        ),
        remediation="Add accessControl to LTM config with tenant/user boundary filters.",
    ))

    # 6. Embedding Isolation
    embedding_isolated = stm_config.get("embeddingIsolation", stm_config.get("embedding_isolation", False))
    sections.append(SessionMemorySection(
        section="Embedding Isolation",
        requirement="User embeddings must not be queryable by other users to prevent information leakage.",
        status="compliant" if embedding_isolated else "partially_compliant",
        finding=(
            "Embedding isolation is enabled." if embedding_isolated
            else "Embedding isolation not explicitly configured — potential cross-user query risk."
        ),
        remediation="Enable embeddingIsolation in STM config.",
    ))

    # 7. Vector DB Row-Level Security
    rls_enabled = stm_config.get("rowLevelSecurity", stm_config.get("row_level_security", False))
    sections.append(SessionMemorySection(
        section="Vector DB Row-Level Security",
        requirement="RAG queries must be filtered by tenant/user ID to prevent cross-tenant retrieval.",
        status="compliant" if rls_enabled else "non_compliant",
        finding=(
            "Row-level security is enabled on vector DB." if rls_enabled
            else "No row-level security — RAG queries may return cross-tenant data."
        ),
        remediation="Enable rowLevelSecurity and add tenant_id filter to all vector queries.",
    ))

    # 8. Session Token Binding
    token_binding = stm_config.get("tokenBinding", stm_config.get("token_binding", False))
    sections.append(SessionMemorySection(
        section="Session Token Binding",
        requirement="Session tokens must be bound to specific memory scope to prevent session hijacking.",
        status="compliant" if token_binding else "partially_compliant",
        finding=(
            "Session tokens are bound to memory scope." if token_binding
            else "Token binding not configured — session tokens may be reusable across scopes."
        ),
        remediation="Enable tokenBinding to tie session tokens to memory scope.",
    ))

    # 9. Data Retention Compliance
    retention_days = stm_config.get("retentionDays", stm_config.get("retention_days", 0))
    has_retention = isinstance(retention_days, int) and retention_days > 0
    sections.append(SessionMemorySection(
        section="Data Retention Compliance",
        requirement="Session data must be auto-purged per retention policy to comply with storage limitation.",
        status="compliant" if has_retention else "non_compliant",
        finding=(
            f"Retention policy is {retention_days} days." if has_retention
            else "No retention policy — session data may persist indefinitely."
        ),
        remediation="Set retentionDays to define automatic data purge schedule.",
    ))

    # 10. Audit Trail for Memory Access
    audit_trail = stm_config.get("auditTrail", stm_config.get("audit_trail", False))
    sections.append(SessionMemorySection(
        section="Audit Trail for Memory Access",
        requirement="All memory read/write operations must be logged for audit purposes.",
        status="compliant" if audit_trail else "partially_compliant",
        finding=(
            "Audit trail is enabled for memory operations." if audit_trail
            else "Audit trail not configured — memory operations are not logged."
        ),
        remediation="Enable auditTrail to log all memory read/write operations.",
    ))

    return sections


def _compute_isolation_score(sections: list[SessionMemorySection]) -> float:
    """Compute isolation score (0.0–1.0) based on section statuses."""
    if not sections:
        return 0.0
    weights = {
        "Session Isolation": 2.0,
        "Embedding Isolation": 1.5,
        "Vector DB Row-Level Security": 2.0,
        "LTM Access Control": 1.5,
        "Session Token Binding": 1.0,
    }
    total_weight = 0.0
    weighted_sum = 0.0
    for s in sections:
        w = weights.get(s.section, 1.0)
        total_weight += w
        if s.status == "compliant":
            weighted_sum += w
        elif s.status == "partially_compliant":
            weighted_sum += w * 0.5
    return round(weighted_sum / max(total_weight, 1.0), 2)


def _derive_risk(ratio: float, isolation_score: float) -> RiskLevel:
    """Derive overall risk level from compliance ratio and isolation score."""
    combined = (ratio + isolation_score) / 2.0
    if combined >= 0.8:
        return RiskLevel.low
    if combined >= 0.6:
        return RiskLevel.medium
    if combined >= 0.4:
        return RiskLevel.high
    return RiskLevel.critical
