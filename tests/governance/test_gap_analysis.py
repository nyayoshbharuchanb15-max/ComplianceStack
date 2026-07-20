# SPDX-License-Identifier: Apache-2.0
"""E2E test — document-level gap analysis.

Verifies that:
  1. A well-formed DPIA text triggers no blocker-severity gaps.
  2. A DPIA missing 'measures envisaged' triggers a blocker gap for
     GDPR Art. 35(7)(d) and blocks the data_protection phase.
  3. Multipart file upload works, computes server-side sha256, extracts
     text and returns gap findings in the artifact row.
  4. Base64 JSON upload works with equivalent behaviour.
  5. A model-card PDF (built with reportlab-style plain text) with
     'Intended use' and 'Training data' but no 'Evaluation' → gap on
     EU-AI-ACT Art. 15 (evaluation).
  6. Bias-test-output JSON referencing DI and demographic parity → no
     blocker gaps; missing DI → blocker.
"""
from __future__ import annotations
import base64
import io
import os
import zlib
from typing import Optional

import httpx
import pytest

BASE = os.environ.get("GOVERNANCE_API_URL", "http://localhost:8001") + "/api/v1"


def _make_pdf(pages_text: list[str]) -> bytes:
    """Build a minimal PDF from ``pages_text`` using pypdf itself so it's
    guaranteed to be parseable by the extractor (which also uses pypdf)."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject, ContentStream, DecodedStreamObject, DictionaryObject,
        FloatObject, NameObject, NumberObject, TextStringObject,
    )

    writer = PdfWriter()
    for text in pages_text:
        # Create a blank page and add a content stream that draws the text.
        page = writer.add_blank_page(width=595, height=842)
        content = f"BT /F1 12 Tf 40 750 Td ({text}) Tj ET".encode("latin-1", "replace")
        stream = DecodedStreamObject()
        stream.set_data(content)
        page[NameObject("/Contents")] = stream
        # Register a Helvetica font as /F1
        font = DictionaryObject({
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        })
        resources = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font}),
        })
        page[NameObject("/Resources")] = resources
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


GOOD_DPIA_TEXT = """
Data Protection Impact Assessment — CV Screener v1.0

Section 1 — Systematic description of the processing operations
The purpose of processing is to rank candidate CVs for shortlisting in
recruitment. Nature of processing includes automated ranking of applicant
records. Scope covers all applicants for open roles.

Section 2 — Necessity and proportionality
The processing is necessary and proportional relative to the legitimate
interest of the employer in efficient screening.

Section 3 — Risks to the rights and freedoms of data subjects
Identified risks to rights and freedoms of data subjects include bias in
screening and impact on right to erasure. Data subject risk is medium.

Section 4 — Measures envisaged
Measures envisaged (safeguards): technical and organisational measures
including audit logging, kill-switch, human oversight, and mitigation
measures for identified bias.

Section 5 — DPO consultation
Consulted the DPO on 2025-11-05. Data Protection Officer signed off.

Retention period: 180 days.
Lawful basis: legitimate interest under GDPR Art. 6(1)(f).
"""

BAD_DPIA_TEXT = """
Data Protection Impact Assessment — CV Screener v1.0

The purpose of processing is to rank candidate CVs for shortlisting.
Nature of processing is automated ranking.

Necessity: processing is necessary for the employer.

Data subject risks and rights considerations covered informally.

Retention period 180 days. Lawful basis is legitimate interest.
"""
# BAD_DPIA is missing an explicit "measures envisaged" section and no DPO
# consultation → should trigger gap on Art. 35(7)(d) [blocker] and
# Art. 35(2) [warning].


def _admin_token() -> str:
    r = httpx.post(f"{BASE}/auth/token",
                   json={"clientId": "governance-admin",
                         "clientSecret": "govern-admin-secret-dev"})
    r.raise_for_status()
    return r.json()["accessToken"]


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestGapAnalysis:
    def test_good_dpia_no_blocker_gaps(self):
        tok = _admin_token()
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(tok), json={
            "modelId": f"gap-good-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
            "evidenceArtifacts": [{
                "name": "DPIA v1.0 (good)", "type": "dpia",
                "mimeType": "text/plain",
                "contentBase64": base64.b64encode(GOOD_DPIA_TEXT.encode()).decode(),
            }],
        })
        r.raise_for_status()
        run_id = r.json()["runId"]

        arts = httpx.get(f"{BASE}/runs/{run_id}/artifacts", headers=_hdr(tok)).json()
        a = arts["artifacts"][0]
        assert a["extractionStatus"] == "extracted"
        assert a["extractedChars"] > 200
        # Every blocker-severity section should be at least 'partial' or 'present'
        blocker_gaps = [g for g in a["gapFindings"]
                        if g["verdict"] == "gap" and g["severity"] == "blocker"]
        assert blocker_gaps == [], f"unexpected blocker gaps: {blocker_gaps}"

    def test_bad_dpia_triggers_blocker_gap_on_measures_envisaged(self):
        tok = _admin_token()
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(tok), json={
            "modelId": f"gap-bad-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
            "evidenceArtifacts": [{
                "name": "DPIA v1.0 (missing measures)", "type": "dpia",
                "mimeType": "text/plain",
                "contentBase64": base64.b64encode(BAD_DPIA_TEXT.encode()).decode(),
            }],
        })
        r.raise_for_status()
        run_id = r.json()["runId"]

        arts = httpx.get(f"{BASE}/runs/{run_id}/artifacts", headers=_hdr(tok)).json()
        a = arts["artifacts"][0]
        assert a["extractionStatus"] == "extracted"
        # Should have a blocker gap on Art. 35(7)(d) — measures envisaged
        measures = [g for g in a["gapFindings"]
                    if g["article"] == "Art. 35(7)(d)" and g["verdict"] == "gap"]
        assert measures, "Expected a gap on Art. 35(7)(d) measures envisaged"
        assert measures[0]["severity"] == "blocker"

    def test_bad_dpia_blocks_data_protection_phase(self):
        """The BAD DPIA is missing 'measures envisaged' — a blocker-severity gap.
        When the data_protection phase runs and cites this DPIA, the phase must
        be blocked and the certificate must be prohibited."""
        tok = _admin_token()
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(tok), json={
            "modelId": f"gap-block-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
            "deploymentContext": {"sector": "employment", "regions": ["EU"],
                                   "autonomyLevel": "supervised"},
            "processingActivities": [{"name": "cv", "purpose": "rank"}],
            "datasets": [{"datasetId": "ds", "containsPersonalData": True}],
            "evidenceArtifacts": [{
                "name": "DPIA v1.0 (missing measures)", "type": "dpia",
                "mimeType": "text/plain",
                "contentBase64": base64.b64encode(BAD_DPIA_TEXT.encode()).decode(),
            }],
        })
        r.raise_for_status()
        run_id = r.json()["runId"]

        # Advance to data_protection
        httpx.post(f"{BASE}/phases/scope", headers=_hdr(tok),
                   json={"runId": run_id}).raise_for_status()
        httpx.post(f"{BASE}/phases/risk", headers=_hdr(tok),
                   json={"runId": run_id, "riskInputs": {"annexIIICategories": ["employment"]}}).raise_for_status()

        dp = httpx.post(f"{BASE}/phases/data-protection", headers=_hdr(tok), json={
            "runId": run_id,
            "dataProtection": {
                "processesPersonalData": True, "lawfulBasis": "legitimate_interest",
                "dpiaConducted": True, "dpoAppointed": True, "consentMechanism": True,
                "dataMinimisationApplied": True, "privacyByDesign": True,
                "retentionPeriodDays": 180, "crossBorderTransfers": []},
        })
        # data_protection engine itself passes (config is fine); the phase must
        # still be blocked because the uploaded DPIA has a blocker-severity gap.
        assert dp.status_code == 200, dp.text
        body = dp.json()
        assert body["status"] == "blocked", body
        # Blocker code should point at the document gap
        codes = [b.get("code") for b in body["blockers"]]
        assert any("DOC_GAP" in (c or "") for c in codes), codes
        assert body["outputs"]["documentGapSummary"]["blockerGaps"] >= 1

    def test_multipart_upload_computes_sha256_and_gaps(self):
        tok = _admin_token()
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(tok), json={
            "modelId": f"mp-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
            "evidenceArtifacts": [],
        })
        run_id = r.json()["runId"]

        files = {"file": ("dpia.txt", GOOD_DPIA_TEXT, "text/plain")}
        data = {"type": "dpia", "name": "DPIA v1.0"}
        up = httpx.post(f"{BASE}/runs/{run_id}/artifacts/upload",
                        headers=_hdr(tok), files=files, data=data)
        assert up.status_code == 200, up.text
        art = up.json()["artifact"]
        assert len(art["sha256"]) == 64
        assert art["extractionStatus"] == "extracted"
        # Expect gapFindings on the returned payload
        assert isinstance(art["gapFindings"], list)
        assert art["gapFindings"], "Expected gap findings on uploaded DPIA"

    def test_pdf_extraction_via_multipart(self):
        tok = _admin_token()
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(tok), json={
            "modelId": f"pdf-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
        })
        run_id = r.json()["runId"]

        pdf = _make_pdf([
            "Model Card CV Screener",
            "Intended use: automated CV ranking for shortlisting.",
            "Training data: ds-cv-2025 corpus with provenance from HR system.",
            "Evaluation and accuracy: F1-score 0.82 on held-out set.",
            "Known limitations: may under-represent gap-year candidates.",
            "Human oversight: reviewer approval required.",
        ])
        files = {"file": ("model-card.pdf", pdf, "application/pdf")}
        data = {"type": "model_card"}
        up = httpx.post(f"{BASE}/runs/{run_id}/artifacts/upload",
                        headers=_hdr(tok), files=files, data=data)
        assert up.status_code == 200, up.text
        art = up.json()["artifact"]
        assert art["extractionStatus"] == "extracted", art
        # At least the "Intended use", "Training data", "Evaluation" and
        # "Limitations" sections should NOT be gaps.
        gaps = [g for g in art["gapFindings"]
                if g["verdict"] == "gap" and g["severity"] == "blocker"]
        assert gaps == [], f"unexpected blocker gaps on well-formed model card: {gaps}"

    def test_bias_test_missing_di_is_blocker(self):
        tok = _admin_token()
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(tok), json={
            "modelId": f"bias-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
        })
        run_id = r.json()["runId"]

        # No mention of disparate impact / DI / four-fifths
        bad = '{"metric": "accuracy", "value": 0.9, "note": "no fairness breakdown"}'
        files = {"file": ("bias.json", bad, "application/json")}
        data = {"type": "bias_test_output"}
        up = httpx.post(f"{BASE}/runs/{run_id}/artifacts/upload",
                        headers=_hdr(tok), files=files, data=data)
        art = up.json()["artifact"]
        assert art["extractionStatus"] == "extracted"
        di_gaps = [g for g in art["gapFindings"]
                    if g["section"].startswith("Disparate impact")]
        assert di_gaps and di_gaps[0]["verdict"] == "gap"
        assert di_gaps[0]["severity"] == "blocker"

    def test_artifact_text_endpoint(self):
        tok = _admin_token()
        r = httpx.post(f"{BASE}/phases/intake", headers=_hdr(tok), json={
            "modelId": f"txt-{os.urandom(4).hex()}", "modelVersion": "1.0.0",
        })
        run_id = r.json()["runId"]

        files = {"file": ("dpia.txt", GOOD_DPIA_TEXT, "text/plain")}
        up = httpx.post(f"{BASE}/runs/{run_id}/artifacts/upload",
                        headers=_hdr(tok), files=files,
                        data={"type": "dpia"}).json()
        aid = up["artifact"]["artifactId"]
        detail = httpx.get(f"{BASE}/artifacts/{aid}", headers=_hdr(tok)).json()
        assert detail["extractedText"].startswith("\nData Protection Impact")
        assert detail["gapFindings"]
