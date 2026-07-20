# SPDX-License-Identifier: Apache-2.0
"""Server-side content extraction for uploaded evidence artifacts.

Extracts a UTF-8 text representation from PDF / CSV / JSON / Markdown / plain
text files so the gap-analysis engines can *scan* the document rather than
only checking presence.

Everything is in-process and offline — no external OCR, no LLM. PDFs are
handled by ``pypdf`` (bundled with the Python service). Files whose type we
can't parse become ``extraction_status='unsupported'`` with the raw sha256
preserved so their citation still counts as "present".
"""
from __future__ import annotations
import csv
import hashlib
import io
import json
from typing import Optional

try:
    import pypdf
except ImportError:  # pragma: no cover — extractor still degrades gracefully
    pypdf = None  # type: ignore[assignment]


MAX_TEXT_CHARS = 300_000   # store up to ~300 KB of extracted text
MAX_ROW_PREVIEW = 500      # csv row preview


def compute_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def extract(content: bytes, mime_type: Optional[str],
            filename: Optional[str] = None) -> tuple[str, str, str]:
    """Return (extracted_text, status, note).

    ``status`` is one of: extracted | partial | unsupported | error.
    """
    if not content:
        return "", "error", "Empty file"

    mt = (mime_type or "").lower()
    fn = (filename or "").lower()

    def is_kind(*needles: str) -> bool:
        return any(n in mt for n in needles) or any(fn.endswith(n) for n in needles)

    try:
        if is_kind("pdf", ".pdf"):
            return _extract_pdf(content)
        if is_kind("csv", ".csv", "text/csv"):
            return _extract_csv(content)
        if is_kind("json", ".json", "application/json"):
            return _extract_json(content)
        if is_kind("markdown", ".md", ".markdown"):
            return _extract_text(content, "markdown")
        if is_kind("text/", ".txt", ".log"):
            return _extract_text(content, "plain-text")
        # Best-effort: try decoding as utf-8
        return _extract_text(content, "unknown-utf8")
    except Exception as e:  # pragma: no cover — defensive
        return "", "error", f"Extraction failed: {e.__class__.__name__}: {e}"


def _extract_pdf(content: bytes) -> tuple[str, str, str]:
    if pypdf is None:
        return "", "unsupported", "pypdf not installed"
    reader = pypdf.PdfReader(io.BytesIO(content))
    pages: list[str] = []
    for i, page in enumerate(reader.pages):
        try:
            pages.append(page.extract_text() or "")
        except Exception as e:  # pragma: no cover
            pages.append(f"[page {i} extraction error: {e}]")
    text = "\n\n".join(pages).strip()
    if not text:
        return "", "partial", "PDF parsed but no extractable text (likely scan-only)"
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS] + "\n\n[…truncated]"
    return text, "extracted", f"{len(reader.pages)} pages, {len(text)} chars"


def _extract_csv(content: bytes) -> tuple[str, str, str]:
    raw = content.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(raw))
    rows = list(reader)
    if not rows:
        return "", "partial", "CSV empty"
    header = rows[0]
    preview = rows[: MAX_ROW_PREVIEW + 1]
    lines = [",".join(header)]
    for r in preview[1:]:
        lines.append(",".join(r))
    text = "\n".join(lines)
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS] + "\n[…truncated]"
    return text, "extracted", f"{len(rows) - 1} data rows, {len(header)} columns"


def _extract_json(content: bytes) -> tuple[str, str, str]:
    try:
        doc = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        return "", "error", f"Malformed JSON: {e.msg} @ line {e.lineno}"
    text = json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False)
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS] + "\n[…truncated]"
    return text, "extracted", f"JSON, {len(text)} chars"


def _extract_text(content: bytes, kind: str) -> tuple[str, str, str]:
    text = content.decode("utf-8", errors="replace")
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS] + "\n[…truncated]"
    return text, "extracted", f"{kind}, {len(text)} chars"
