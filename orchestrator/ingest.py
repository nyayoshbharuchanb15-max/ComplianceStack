# SPDX-License-Identifier: Apache-2.0
"""Ingest pipeline for evidence artifacts.

Called on every artifact submission (via the intake payload or via the
/runs/:id/artifacts endpoints — multipart or JSON). Encapsulates:

  1. Compute the server-side sha256 over the raw bytes (or over a canonical
     JSON descriptor when the caller only supplied a URI).
  2. Extract UTF-8 text (PDF via pypdf, CSV, JSON, MD, TXT).
  3. Run the document gap analyzer for the artifact type.
  4. Persist the artifact row (with extracted text & gap findings).

This is a strict single-source-of-truth for artifact side effects, so both
the human workbench and MCP-agent flows produce identical evidence rows.
"""
from __future__ import annotations
import base64
from typing import Any, Optional

from engines import document_extractor, gap_analysis
from store import artifacts as artifact_store


def _sha256_of_bytes(payload: bytes) -> str:
    return document_extractor.compute_sha256(payload)


async def ingest_artifact_bytes(run_id: str, artifact_meta: dict,
                                content: bytes, submitted_by: str) -> dict:
    """Ingest an artifact whose raw content is available (multipart upload).

    Computes sha256 over the actual bytes, extracts text, runs gap analysis,
    persists everything, returns the resulting artifact summary.
    """
    sha = _sha256_of_bytes(content)
    text, status, note = document_extractor.extract(
        content, artifact_meta.get("mimeType"), artifact_meta.get("name"))

    # Give the meta a computed sha256 + sizeBytes so insert_artifact writes them.
    meta = {**artifact_meta,
            "sha256": sha,
            "sizeBytes": len(content),
            # keep the first 4 KB as content_snippet for quick UI preview
            "contentSnippet": (text[:4000] if text else None)}

    inserted = await artifact_store.insert_artifact(
        run_id, meta, submitted_by=submitted_by,
        extracted_text=text or None,
        extraction_status=status, extraction_note=note)

    # Run gap analysis on the extracted text and persist findings on the row.
    findings, score = gap_analysis.analyze_document(
        meta.get("type", "other"), text or "", {"artifactId": inserted["artifactId"]})
    await artifact_store.update_artifact_gaps(inserted["artifactId"], findings, score)

    inserted["gapScore"] = score
    inserted["gapFindings"] = findings
    inserted["extractionStatus"] = status
    inserted["extractionNote"] = note
    return inserted


async def ingest_artifact_descriptor(run_id: str, artifact_meta: dict,
                                     submitted_by: str) -> dict:
    """Ingest an artifact submitted only as a descriptor (name/type/uri, no bytes).

    We can't extract text without content; if a ``contentSnippet`` was
    supplied we run the gap analyzer over it (a partial signal is better than
    none). Otherwise the artifact is stored with ``extraction_status='pending'``.
    """
    snippet = artifact_meta.get("contentSnippet")
    if snippet:
        text = snippet
        status, note = "extracted", f"caller-supplied snippet, {len(snippet)} chars"
    else:
        text, status, note = None, "pending", "No bytes submitted — descriptor only"

    inserted = await artifact_store.insert_artifact(
        run_id, artifact_meta, submitted_by=submitted_by,
        extracted_text=text, extraction_status=status,
        extraction_note=note)

    findings, score = gap_analysis.analyze_document(
        artifact_meta.get("type", "other"), text or "",
        {"artifactId": inserted["artifactId"]})
    # When there's no text at all, findings will list every expected section
    # as 'gap' — but they carry severity so we don't over-block descriptors.
    await artifact_store.update_artifact_gaps(inserted["artifactId"], findings, score)

    inserted["gapScore"] = score
    inserted["gapFindings"] = findings
    inserted["extractionStatus"] = status
    inserted["extractionNote"] = note
    return inserted


async def ingest_artifact_base64(run_id: str, artifact_meta: dict,
                                 b64_content: str, submitted_by: str) -> dict:
    """Ingest an artifact whose content was submitted as base64 (JSON body)."""
    try:
        content = base64.b64decode(b64_content, validate=True)
    except Exception as e:  # base64.binascii.Error
        raise ValueError(f"Invalid base64 content: {e}") from e
    return await ingest_artifact_bytes(run_id, artifact_meta, content, submitted_by)
