# SPDX-License-Identifier: Apache-2.0
"""Evidence artifacts + per-phase article-level citations.

An **artifact** is a document or record submitted (by a human auditor or an AI
agent via MCP) as evidence for an audit run — e.g. Model Card, DPIA, dataset
lineage record, bias-test output, robustness log, explainability report.

A **citation** is the auditor's record of which artifact was inspected against
which regulatory article, with a verdict (present | pass | warning | fail |
missing). Citations answer the question "which specific document proved (or
failed to prove) compliance against this control?".
"""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from store.db import db


ARTIFACT_TYPES = [
    "model_card", "dpia", "dataset_lineage", "training_log",
    "bias_test_output", "fairness_metrics_report",
    "robustness_test_log", "security_audit", "adversarial_test_report",
    "explainability_report", "decision_log_sample",
    "oversight_procedure", "kill_switch_evidence",
    "consent_ux_evidence", "data_flow_map", "ropa_record",
    "risk_assessment", "conformity_declaration",
    "monitoring_dashboard", "incident_report",
    "other",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _artifact_id() -> str:
    return "art_" + uuid.uuid4().hex[:16]


def compute_sha256(payload: dict) -> str:
    """Deterministic sha256 for artifact content-integrity (canonical JSON)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ─── Artifact CRUD ───────────────────────────────────────────────

async def insert_artifact(run_id: str, artifact: dict, submitted_by: str,
                          extracted_text: Optional[str] = None,
                          extraction_status: str = "pending",
                          extraction_note: Optional[str] = None,
                          storage_path: Optional[str] = None) -> dict:
    aid = artifact.get("artifactId") or _artifact_id()
    name = artifact.get("name") or aid
    a_type = artifact.get("type") or "other"
    mime = artifact.get("mimeType") or None
    uri = artifact.get("uri") or None
    snippet = artifact.get("contentSnippet")
    if snippet and len(snippet) > 4000:
        snippet = snippet[:4000] + "…[truncated]"
    tags = artifact.get("tags") or []
    sha = (artifact.get("sha256")
           or compute_sha256({"name": name, "type": a_type, "uri": uri,
                              "snippet": snippet}))
    size = artifact.get("sizeBytes")
    extracted_at = _now() if extracted_text is not None else None
    async with db.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO governance_artifacts
                   (artifact_id, run_id, name, artifact_type, mime_type, uri,
                    content_snippet, sha256, size_bytes, tags, submitted_by,
                    submitted_at, storage_path, extracted_text, extracted_at,
                    extraction_status, extraction_note)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,
                       $13,$14,$15,$16,$17)""",
            aid, run_id, name, a_type, mime, uri, snippet, sha, size,
            json.dumps(tags), submitted_by, _now(),
            storage_path, extracted_text, extracted_at,
            extraction_status, extraction_note)
    return {"artifactId": aid, "sha256": sha, "type": a_type, "name": name,
            "extractionStatus": extraction_status,
            "extractionNote": extraction_note}


async def update_artifact_gaps(artifact_id: str, gap_findings: list[dict],
                                gap_score: float) -> None:
    async with db.pool.acquire() as conn:
        await conn.execute(
            """UPDATE governance_artifacts
               SET gap_findings=$1::jsonb, gap_score=$2
               WHERE artifact_id=$3""",
            json.dumps(gap_findings), gap_score, artifact_id)


async def list_artifacts(run_id: str) -> list[dict]:
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT artifact_id, name, artifact_type, mime_type, uri,
                      content_snippet, sha256, size_bytes, tags, submitted_by,
                      submitted_at, extraction_status, extraction_note,
                      extracted_at, gap_findings, gap_score,
                      LENGTH(COALESCE(extracted_text,'')) AS extracted_chars
               FROM governance_artifacts WHERE run_id=$1
               ORDER BY submitted_at ASC""", run_id)
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        d["artifactId"] = d.pop("artifact_id")
        d["type"] = d.pop("artifact_type")
        d["mimeType"] = d.pop("mime_type")
        d["contentSnippet"] = d.pop("content_snippet")
        d["sizeBytes"] = d.pop("size_bytes")
        d["submittedBy"] = d.pop("submitted_by")
        d["extractionStatus"] = d.pop("extraction_status")
        d["extractionNote"] = d.pop("extraction_note")
        d["extractedAt"] = (d.pop("extracted_at").isoformat()
                             if isinstance(d.get("extracted_at"), datetime)
                             else d.get("extracted_at"))
        d["gapScore"] = float(d["gap_score"]) if d.get("gap_score") is not None else None
        d.pop("gap_score", None)
        d["extractedChars"] = d.pop("extracted_chars")
        if isinstance(d.get("tags"), str):
            d["tags"] = json.loads(d["tags"])
        if isinstance(d.get("gap_findings"), str):
            d["gapFindings"] = json.loads(d["gap_findings"])
        else:
            d["gapFindings"] = d.get("gap_findings") or []
        d.pop("gap_findings", None)
        sa = d.get("submitted_at")
        if isinstance(sa, datetime):
            d["submittedAt"] = sa.isoformat()
        elif sa is not None:
            d["submittedAt"] = sa
        d.pop("submitted_at", None)
        out.append(d)
    return out


async def get_artifact_text(artifact_id: str) -> Optional[dict]:
    """Fetch the full extracted text of a single artifact for inline preview."""
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT artifact_id, name, artifact_type, mime_type,
                      extracted_text, extraction_status, extraction_note,
                      gap_findings, gap_score
               FROM governance_artifacts WHERE artifact_id=$1""", artifact_id)
    if not row:
        return None
    d = dict(row)
    return {
        "artifactId": d["artifact_id"], "name": d["name"],
        "type": d["artifact_type"], "mimeType": d["mime_type"],
        "extractedText": d["extracted_text"] or "",
        "extractionStatus": d["extraction_status"],
        "extractionNote": d["extraction_note"],
        "gapScore": float(d["gap_score"]) if d.get("gap_score") is not None else None,
        "gapFindings": (json.loads(d["gap_findings"])
                        if isinstance(d["gap_findings"], str)
                        else (d["gap_findings"] or [])),
    }


async def get_artifacts_by_type(run_id: str, artifact_type: str) -> list[dict]:
    """Return artifacts of a specific type submitted for this run."""
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT artifact_id, name, artifact_type, sha256, uri, tags,
                      extraction_status, extracted_text, gap_findings, gap_score
               FROM governance_artifacts WHERE run_id=$1 AND artifact_type=$2
               ORDER BY submitted_at ASC""", run_id, artifact_type)
    out = []
    for r in rows:
        d = dict(r)
        d["artifactId"] = d.pop("artifact_id")
        d["type"] = d.pop("artifact_type")
        if isinstance(d.get("tags"), str):
            d["tags"] = json.loads(d["tags"])
        d["extractionStatus"] = d.pop("extraction_status")
        d["extractedText"] = d.pop("extracted_text") or ""
        d["gapScore"] = float(d["gap_score"]) if d.get("gap_score") is not None else None
        d.pop("gap_score", None)
        if isinstance(d.get("gap_findings"), str):
            d["gapFindings"] = json.loads(d["gap_findings"])
        else:
            d["gapFindings"] = d.get("gap_findings") or []
        d.pop("gap_findings", None)
        out.append(d)
    return out


# ─── Phase gaps ──────────────────────────────────────────────────

async def insert_phase_gaps(run_id: str, phase_key: str,
                            gaps: list[dict]) -> None:
    if not gaps:
        return
    async with db.pool.acquire() as conn:
        await conn.executemany(
            """INSERT INTO governance_phase_gaps
                   (run_id, phase_key, artifact_id, framework, article,
                    section, verdict, severity, evidence_span, note, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)""",
            [(run_id, phase_key, g["artifactId"], g["framework"], g["article"],
              g["section"], g["verdict"], g["severity"],
              g.get("evidenceSpan"), g.get("note"), _now())
             for g in gaps if g.get("artifactId")])


async def list_phase_gaps(run_id: str,
                          phase_key: Optional[str] = None) -> list[dict]:
    q = ("""SELECT g.phase_key, g.artifact_id, g.framework, g.article,
                    g.section, g.verdict, g.severity, g.evidence_span, g.note,
                    g.created_at, a.name AS artifact_name,
                    a.artifact_type AS artifact_type
             FROM governance_phase_gaps g
             LEFT JOIN governance_artifacts a ON a.artifact_id=g.artifact_id
             WHERE g.run_id=$1""")
    args: list[Any] = [run_id]
    if phase_key:
        q += " AND g.phase_key=$2"
        args.append(phase_key)
    q += " ORDER BY g.phase_key ASC, g.created_at ASC"
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(q, *args)
    out = []
    for r in rows:
        d = dict(r)
        out.append({
            "phaseKey": d["phase_key"], "artifactId": d["artifact_id"],
            "artifactName": d["artifact_name"],
            "artifactType": d["artifact_type"],
            "framework": d["framework"], "article": d["article"],
            "section": d["section"], "verdict": d["verdict"],
            "severity": d["severity"], "evidenceSpan": d["evidence_span"],
            "note": d["note"],
            "createdAt": d["created_at"].isoformat() if isinstance(
                d.get("created_at"), datetime) else d.get("created_at"),
        })
    return out


# ─── Citations ───────────────────────────────────────────────────

async def insert_citations(run_id: str, phase_key: str, citations: list[dict]) -> None:
    if not citations:
        return
    async with db.pool.acquire() as conn:
        await conn.executemany(
            """INSERT INTO governance_phase_citations
                   (run_id, phase_key, artifact_id, expected_type, framework,
                    article, control, verdict, note, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
            [(run_id, phase_key, c.get("artifactId"), c["expectedType"],
              c["framework"], c["article"], c["control"], c["verdict"],
              c.get("note", ""), _now())
             for c in citations])


async def list_citations(run_id: str,
                         phase_key: Optional[str] = None) -> list[dict]:
    q = ("""SELECT c.phase_key, c.artifact_id, c.expected_type, c.framework,
                    c.article, c.control, c.verdict, c.note, c.created_at,
                    a.name AS artifact_name, a.artifact_type AS artifact_type,
                    a.sha256 AS artifact_sha256, a.uri AS artifact_uri
             FROM governance_phase_citations c
             LEFT JOIN governance_artifacts a ON a.artifact_id = c.artifact_id
             WHERE c.run_id=$1""")
    args: list[Any] = [run_id]
    if phase_key:
        q += " AND c.phase_key=$2"
        args.append(phase_key)
    q += " ORDER BY c.phase_key ASC, c.created_at ASC"
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(q, *args)
    out = []
    for r in rows:
        d = dict(r)
        out.append({
            "phaseKey": d["phase_key"],
            "artifactId": d["artifact_id"],
            "artifactName": d["artifact_name"],
            "artifactType": d["artifact_type"],
            "artifactSha256": d["artifact_sha256"],
            "artifactUri": d["artifact_uri"],
            "expectedType": d["expected_type"],
            "framework": d["framework"],
            "article": d["article"],
            "control": d["control"],
            "verdict": d["verdict"],
            "note": d["note"],
            "createdAt": d["created_at"].isoformat() if isinstance(
                d.get("created_at"), datetime) else d.get("created_at"),
        })
    return out
