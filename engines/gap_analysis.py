# SPDX-License-Identifier: Apache-2.0
"""Document-level gap analysis — the diagnostic core.

For every artifact type that ships as a document (DPIA, model card, bias/fairness
report, robustness log, explainability report, oversight procedure, etc.), we
declare a *specification*: a list of sections/fields that the document is
expected to cover, each mapped to a specific regulatory sub-article and clause.

A gap analyzer takes an artifact's extracted text and produces per-section
findings::

    {
      "artifactId": "art_…",
      "artifactType": "dpia",
      "framework": "GDPR",
      "article": "Art. 35",
      "section": "Art. 35(7)(a) — systematic description",
      "verdict": "present" | "partial" | "gap",
      "severity": "info" | "warning" | "blocker",
      "evidenceSpan": "…first matching excerpt from the document…",
      "note": "…human-readable diagnosis…",
    }

Gaps of severity ``blocker`` block the phase; ``warning`` become soft findings
that surface in the citation verdict; ``info`` are informational only.

The engine is 100 % deterministic (regex + keyword scoring) and 100 %
in-process — no LLM, no external service — so results are reproducible and
auditable.
"""
from __future__ import annotations
import re
from typing import Any


# ─── Specification ───────────────────────────────────────────────

# each spec: {section, keywords[], framework, article, severity_if_missing, note?}
# keywords are OR'd (any hit → section is at least "partial"); a section with
# ≥2 keyword hits within 400 chars of each other is "present".

SPECIFICATIONS: dict[str, list[dict[str, Any]]] = {
    "dpia": [
        {"section": "Art. 35(7)(a) — Systematic description of processing",
         "keywords": [r"systematic description", r"purpose[s]? of (the )?processing",
                      r"nature of (the )?processing", r"scope of processing"],
         "framework": "GDPR", "article": "Art. 35(7)(a)", "severity": "blocker"},
        {"section": "Art. 35(7)(b) — Necessity and proportionality",
         "keywords": [r"necess(?:ary|ity)", r"proportional(?:ity)?"],
         "framework": "GDPR", "article": "Art. 35(7)(b)", "severity": "blocker"},
        {"section": "Art. 35(7)(c) — Risks to rights and freedoms",
         "keywords": [r"risk[s]? to (the )?rights?", r"rights? and freedoms?",
                      r"data subject[s]? risk"],
         "framework": "GDPR", "article": "Art. 35(7)(c)", "severity": "blocker"},
        {"section": "Art. 35(7)(d) — Measures envisaged (safeguards)",
         "keywords": [r"measure[s]? envisaged", r"safeguard[s]?",
                      r"mitigat(?:ion|ing) measure", r"technical and organi[zs]ational measures"],
         "framework": "GDPR", "article": "Art. 35(7)(d)", "severity": "blocker"},
        {"section": "Art. 35(2) — DPO consultation",
         "keywords": [r"data protection officer", r"\bDPO\b consult", r"consulted the DPO"],
         "framework": "GDPR", "article": "Art. 35(2)", "severity": "warning"},
        {"section": "Retention period declared",
         "keywords": [r"retention period", r"retained for", r"data retention"],
         "framework": "GDPR", "article": "Art. 5(1)(e)", "severity": "warning"},
        {"section": "Lawful basis declared",
         "keywords": [r"lawful basis", r"legal basis", r"legitimate interest",
                      r"\bconsent\b", r"contractual necessity"],
         "framework": "GDPR", "article": "Art. 6", "severity": "warning"},
    ],
    "model_card": [
        {"section": "Intended use / deployment context",
         "keywords": [r"intended use", r"intended purpose", r"deployment context"],
         "framework": "EU-AI-ACT", "article": "Art. 13(3)(b)", "severity": "blocker"},
        {"section": "Out-of-scope / prohibited uses",
         "keywords": [r"out.?of.?scope", r"prohibited use", r"not intended for",
                      r"foreseeable misuse"],
         "framework": "EU-AI-ACT", "article": "Art. 13(3)(b)(iii)", "severity": "warning"},
        {"section": "Training data — provenance and composition",
         "keywords": [r"training data", r"data source", r"dataset composition",
                      r"provenance"],
         "framework": "EU-AI-ACT", "article": "Art. 10", "severity": "blocker"},
        {"section": "Evaluation / performance metrics",
         "keywords": [r"evaluation", r"performance metric", r"accuracy", r"F1[- ]?score",
                      r"benchmark result"],
         "framework": "EU-AI-ACT", "article": "Art. 15", "severity": "blocker"},
        {"section": "Known limitations",
         "keywords": [r"limitation[s]?", r"known limitation", r"\bcaveat"],
         "framework": "EU-AI-ACT", "article": "Art. 13(3)(b)(iii)", "severity": "warning"},
        {"section": "Bias / fairness considerations",
         "keywords": [r"bias", r"fairness", r"demographic parity",
                      r"disparate impact"],
         "framework": "EU-AI-ACT", "article": "Art. 10(2)(f)", "severity": "warning"},
        {"section": "Human oversight recommendations",
         "keywords": [r"human oversight", r"human.?in.?the.?loop",
                      r"human review"],
         "framework": "EU-AI-ACT", "article": "Art. 14", "severity": "warning"},
    ],
    "bias_test_output": [
        {"section": "Disparate impact ratio reported",
         "keywords": [r"disparate impact", r"\bDI\b", r"four.?fifths?"],
         "framework": "EU-AI-ACT", "article": "Art. 10(2)(f)", "severity": "blocker"},
        {"section": "Sensitive attribute(s) enumerated",
         "keywords": [r"sensitive (?:attribute|feature)", r"protected class",
                      r"gender", r"\brace\b", r"\bage\b"],
         "framework": "EU-AI-ACT", "article": "Art. 10(2)(f)", "severity": "blocker"},
        {"section": "Demographic parity or equal-opportunity metric",
         "keywords": [r"demographic parity", r"equal opportunity",
                      r"equalised odds", r"equalized odds"],
         "framework": "NIST-AI-RMF", "article": "MEASURE 2.2", "severity": "warning"},
        {"section": "Fairness threshold and pass/fail declared",
         "keywords": [r"threshold", r"pass(?:ed)?/fail", r"acceptance criterion"],
         "framework": "EU-AI-ACT", "article": "Art. 10(4)", "severity": "warning"},
    ],
    "fairness_metrics_report": [
        {"section": "Per-group selection rates",
         "keywords": [r"selection rate", r"positive rate", r"outcome rate"],
         "framework": "NIST-AI-RMF", "article": "MEASURE 2.2", "severity": "blocker"},
        {"section": "Equal-opportunity difference",
         "keywords": [r"equal.?opportunity", r"TPR difference",
                      r"true.?positive.?rate"],
         "framework": "NIST-AI-RMF", "article": "MEASURE 2.2", "severity": "warning"},
        {"section": "Mitigation strategy",
         "keywords": [r"mitigation", r"debiasing", r"resampling",
                      r"reweight(?:ing)?"],
         "framework": "EU-AI-ACT", "article": "Art. 10(2)(g)", "severity": "warning"},
    ],
    "robustness_test_log": [
        {"section": "Prompt-injection resilience test result",
         "keywords": [r"prompt injection", r"prompt.injection resistance"],
         "framework": "EU-AI-ACT", "article": "Art. 15(4)", "severity": "blocker"},
        {"section": "Jailbreak / evasion test coverage",
         "keywords": [r"jailbreak", r"evasion", r"bypass"],
         "framework": "EU-AI-ACT", "article": "Art. 15(4)", "severity": "warning"},
        {"section": "Adversarial input resistance metric",
         "keywords": [r"adversarial", r"perturbation", r"attack success rate"],
         "framework": "NIST-AI-RMF", "article": "MEASURE 2.7", "severity": "blocker"},
        {"section": "Rate-limiting / throttling controls",
         "keywords": [r"rate limit", r"throttl(?:e|ing)", r"quota"],
         "framework": "ISO-42001", "article": "Clause 8.1.3", "severity": "warning"},
    ],
    "adversarial_test_report": [
        {"section": "Attack corpus and pass rate",
         "keywords": [r"attack (?:corpus|suite)", r"pass rate",
                      r"attack success rate", r"resistance rate"],
         "framework": "EU-AI-ACT", "article": "Art. 15", "severity": "blocker"},
        {"section": "Red-team methodology",
         "keywords": [r"red.?team", r"methodology", r"threat model"],
         "framework": "NIST-AI-RMF", "article": "MEASURE 2.7", "severity": "warning"},
    ],
    "security_audit": [
        {"section": "Vulnerability findings enumerated",
         "keywords": [r"vulnerabilit(?:y|ies)", r"finding[s]?", r"\bCVE-"],
         "framework": "ISO-42001", "article": "Clause 8.1.3", "severity": "warning"},
        {"section": "Access control review",
         "keywords": [r"access control", r"authenti(?:cation|zation)",
                      r"\bRBAC\b", r"least privilege"],
         "framework": "ISO-42001", "article": "Clause 8.1.3", "severity": "warning"},
    ],
    "explainability_report": [
        {"section": "Explanation method declared",
         "keywords": [r"\bSHAP\b", r"\bLIME\b", r"integrated gradient",
                      r"attention map", r"explanation method"],
         "framework": "EU-AI-ACT", "article": "Art. 13(3)(d)", "severity": "blocker"},
        {"section": "User-facing explanation format",
         "keywords": [r"user.?facing", r"end.?user explanation",
                      r"human-readable"],
         "framework": "EU-AI-ACT", "article": "Art. 13(3)(d)", "severity": "warning"},
        {"section": "Global vs local explanation coverage",
         "keywords": [r"local explanation", r"global explanation",
                      r"feature importance"],
         "framework": "NIST-AI-RMF", "article": "MEASURE 2.9", "severity": "warning"},
    ],
    "decision_log_sample": [
        {"section": "Decision timestamp",
         "keywords": [r"timestamp", r"decided.at", r"\bts\b",
                      r"20[0-9]{2}-[01][0-9]-[0-3][0-9]"],
         "framework": "EU-AI-ACT", "article": "Art. 12", "severity": "blocker"},
        {"section": "Input hash / trace id",
         "keywords": [r"input.hash", r"trace.?id", r"request.?id",
                      r"correlation.?id"],
         "framework": "EU-AI-ACT", "article": "Art. 12", "severity": "warning"},
        {"section": "Reviewer / oversight actor",
         "keywords": [r"reviewer", r"oversight", r"approver", r"decision.maker"],
         "framework": "EU-AI-ACT", "article": "Art. 14", "severity": "warning"},
    ],
    "oversight_procedure": [
        {"section": "Human-in-the-loop step described",
         "keywords": [r"human.?in.?the.?loop", r"human review",
                      r"manual approval"],
         "framework": "EU-AI-ACT", "article": "Art. 14(4)(a)", "severity": "blocker"},
        {"section": "Override / stop capability",
         "keywords": [r"override", r"stop", r"halt", r"kill.?switch",
                      r"intervention"],
         "framework": "EU-AI-ACT", "article": "Art. 14(4)(e)", "severity": "blocker"},
        {"section": "Named oversight roles",
         "keywords": [r"role[s]?", r"reviewer", r"compliance officer",
                      r"data steward"],
         "framework": "EU-AI-ACT", "article": "Art. 14(4)(b)", "severity": "warning"},
    ],
    "kill_switch_evidence": [
        {"section": "Stop trigger / runbook step",
         "keywords": [r"trigger", r"runbook", r"halt", r"stop procedure"],
         "framework": "EU-AI-ACT", "article": "Art. 14(4)(e)", "severity": "blocker"},
        {"section": "Response / rollback SLA",
         "keywords": [r"\bSLA\b", r"response time", r"rollback",
                      r"time to disable"],
         "framework": "ISO-42001", "article": "Clause 8.3", "severity": "warning"},
    ],
    "data_flow_map": [
        {"section": "Data source(s) enumerated",
         "keywords": [r"data source", r"upstream", r"ingested from",
                      r"provider"],
         "framework": "GDPR", "article": "Art. 30", "severity": "warning"},
        {"section": "Cross-border transfer path",
         "keywords": [r"cross.border", r"international transfer",
                      r"third country", r"outside EEA"],
         "framework": "GDPR", "article": "Art. 44", "severity": "warning"},
    ],
    "ropa_record": [
        {"section": "Purposes of processing",
         "keywords": [r"purposes? of (the )?processing", r"processing purpose"],
         "framework": "GDPR", "article": "Art. 30(1)(b)", "severity": "blocker"},
        {"section": "Categories of data subjects & data",
         "keywords": [r"categor(?:y|ies) of data subjects?",
                      r"categor(?:y|ies) of personal data",
                      r"data subject categor"],
         "framework": "GDPR", "article": "Art. 30(1)(c)", "severity": "blocker"},
        {"section": "Retention periods",
         "keywords": [r"retention period", r"erasure period"],
         "framework": "GDPR", "article": "Art. 30(1)(f)", "severity": "warning"},
    ],
    "dataset_lineage": [
        {"section": "Source and version",
         "keywords": [r"source", r"version", r"provenance"],
         "framework": "EU-AI-ACT", "article": "Art. 10(3)", "severity": "blocker"},
        {"section": "Preprocessing / cleaning steps",
         "keywords": [r"preprocess", r"clean(?:ing|ed)", r"deduplication",
                      r"transformation"],
         "framework": "EU-AI-ACT", "article": "Art. 10(3)", "severity": "warning"},
        {"section": "Split description (train/val/test)",
         "keywords": [r"train(?:ing)?[ /]?(?:val|validation)[ /]?test",
                      r"split[s]?", r"train.?test"],
         "framework": "EU-AI-ACT", "article": "Art. 10(3)", "severity": "warning"},
    ],
    "risk_assessment": [
        {"section": "Risk identification",
         "keywords": [r"identif(?:y|ied) risk", r"risk register",
                      r"threat identification"],
         "framework": "EU-AI-ACT", "article": "Art. 9", "severity": "blocker"},
        {"section": "Risk mitigation",
         "keywords": [r"mitigation", r"risk treatment", r"control[s]?"],
         "framework": "EU-AI-ACT", "article": "Art. 9(2)(d)", "severity": "warning"},
    ],
    "conformity_declaration": [
        {"section": "Signatory / issuer",
         "keywords": [r"signed by", r"issued by", r"declarant"],
         "framework": "EU-AI-ACT", "article": "Art. 47", "severity": "warning"},
        {"section": "Referenced standards",
         "keywords": [r"harmonised standard", r"ISO", r"IEC", r"CEN"],
         "framework": "EU-AI-ACT", "article": "Art. 40", "severity": "warning"},
    ],
    "monitoring_dashboard": [
        {"section": "Drift metric surfaced",
         "keywords": [r"drift", r"population stability", r"\bPSI\b"],
         "framework": "EU-AI-ACT", "article": "Art. 72", "severity": "warning"},
        {"section": "Fairness monitoring metric",
         "keywords": [r"fairness", r"disparate impact", r"parity"],
         "framework": "EU-AI-ACT", "article": "Art. 72", "severity": "warning"},
    ],
    "incident_report": [
        {"section": "Incident timeline",
         "keywords": [r"timeline", r"chronology", r"detected at"],
         "framework": "EU-AI-ACT", "article": "Art. 73", "severity": "blocker"},
        {"section": "Root cause analysis",
         "keywords": [r"root cause", r"\bRCA\b", r"cause analysis"],
         "framework": "EU-AI-ACT", "article": "Art. 73", "severity": "warning"},
        {"section": "Corrective action",
         "keywords": [r"corrective action", r"remediation", r"fix applied"],
         "framework": "ISO-42001", "article": "Clause 10.2", "severity": "warning"},
    ],
    "consent_ux_evidence": [
        {"section": "Consent choice presented",
         "keywords": [r"\bconsent\b", r"opt.?in", r"\bagree\b",
                      r"\bI accept"],
         "framework": "GDPR", "article": "Art. 7", "severity": "blocker"},
        {"section": "Withdraw / opt-out path",
         "keywords": [r"withdraw", r"opt.?out", r"revoke"],
         "framework": "GDPR", "article": "Art. 7(3)", "severity": "warning"},
    ],
    "training_log": [
        {"section": "Hyperparameters recorded",
         "keywords": [r"hyperparameter", r"learning rate", r"batch size",
                      r"epoch"],
         "framework": "EU-AI-ACT", "article": "Art. 11(1)(c)", "severity": "warning"},
        {"section": "Training metrics per epoch",
         "keywords": [r"epoch", r"loss", r"validation loss", r"accuracy"],
         "framework": "EU-AI-ACT", "article": "Art. 11(1)(c)", "severity": "warning"},
    ],
}


# ─── Analyzer ────────────────────────────────────────────────────

_WORD = re.compile(r"\W+")


def _normalize(text: str) -> str:
    """Lowercase and collapse whitespace for keyword matching."""
    return re.sub(r"\s+", " ", text.lower())


def _first_span(text: str, pattern: re.Pattern, window: int = 160) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    start = max(0, m.start() - window // 2)
    end = min(len(text), m.end() + window // 2)
    excerpt = text[start:end].replace("\n", " ").strip()
    return f"…{excerpt}…" if excerpt else ""


def _match_all(text: str, patterns: list[re.Pattern]) -> list[re.Match]:
    hits = []
    for p in patterns:
        for m in p.finditer(text):
            hits.append(m)
    hits.sort(key=lambda m: m.start())
    return hits


def analyze_document(artifact_type: str, extracted_text: str,
                     artifact: dict[str, Any]) -> tuple[list[dict], float]:
    """Analyze one artifact's text against its type specification.

    Returns (findings, gap_score) where gap_score ∈ [0, 1] and is
    #present_or_partial / #total_sections.

    When ``extracted_text`` is empty the analyzer emits informational-only
    gap rows (severity forced to 'info') so descriptor-only uploads don't
    generate false blockers — the caller must actually upload bytes to
    receive a diagnostic gap analysis.
    """
    spec = SPECIFICATIONS.get(artifact_type)
    if not spec:
        return [], 1.0  # no spec → don't penalise
    if not extracted_text:
        # No text to scan — emit "pending analysis" rows at severity=info so
        # the UI shows the expected sections without escalating to blockers.
        out = []
        for s in spec:
            out.append({
                "artifactId": artifact.get("artifactId"),
                "artifactType": artifact_type,
                "framework": s["framework"], "article": s["article"],
                "section": s["section"], "verdict": "pending",
                "severity": "info", "evidenceSpan": "",
                "note": ("Content not submitted — upload the actual document "
                         "to enable section-level gap analysis for "
                         f"{s['framework']} {s['article']}."),
            })
        return out, 1.0  # neutral score for descriptor-only artifacts

    lowered = _normalize(extracted_text)
    findings: list[dict] = []
    scored = 0.0

    for s in spec:
        patterns = [re.compile(k, re.IGNORECASE) for k in s["keywords"]]
        hits = _match_all(lowered, patterns)
        n = len(hits)
        if n == 0:
            findings.append({
                "artifactId": artifact.get("artifactId"),
                "artifactType": artifact_type,
                "framework": s["framework"], "article": s["article"],
                "section": s["section"], "verdict": "gap",
                "severity": s["severity"], "evidenceSpan": "",
                "note": (f"Section not found in the document. "
                         f"Expected any of: {', '.join(s['keywords'])}."),
            })
            continue

        verdict = "present" if n >= 2 else "partial"
        scored += 1.0 if verdict == "present" else 0.5
        # Take the excerpt from the ORIGINAL text (case preserved) using the
        # same regex on the original.
        orig_patterns = [re.compile(k, re.IGNORECASE) for k in s["keywords"]]
        excerpt = ""
        for op in orig_patterns:
            excerpt = _first_span(extracted_text, op) or excerpt
            if excerpt:
                break
        findings.append({
            "artifactId": artifact.get("artifactId"),
            "artifactType": artifact_type,
            "framework": s["framework"], "article": s["article"],
            "section": s["section"], "verdict": verdict,
            "severity": "info" if verdict == "present" else s["severity"],
            "evidenceSpan": excerpt,
            "note": ("Section evidenced by matching phrase in the document."
                     if verdict == "present"
                     else "Only one keyword matched — treat as partial "
                          "coverage; recommend an explicit section header."),
        })

    gap_score = scored / len(spec) if spec else 1.0
    return findings, round(gap_score, 4)


def rollup_phase_blockers(gap_findings: list[dict], phase_key: str) -> list[dict]:
    """Convert artifact-level gap findings into phase-level blockers.

    A finding is promoted to a phase blocker iff severity == 'blocker' AND
    verdict == 'gap'. Duplicates on (framework, article, section) are merged.
    """
    seen = set()
    blockers: list[dict] = []
    for g in gap_findings:
        if g["severity"] == "blocker" and g["verdict"] == "gap":
            key = (g["framework"], g["article"], g["section"])
            if key in seen:
                continue
            seen.add(key)
            blockers.append({
                "code": f"DOC_GAP_{phase_key.upper()}",
                "framework": g["framework"], "article": g["article"],
                "reason": (f"Uploaded {g['artifactType']} is missing the "
                           f"'{g['section']}' section — cannot evidence "
                           f"{g['framework']} {g['article']}."),
                "remediation": ("Add the missing section to the source "
                                "document (or upload a superseding artifact) "
                                "and re-run this phase."),
                "gapSection": g["section"], "artifactId": g["artifactId"],
                "artifactType": g["artifactType"],
            })
    return blockers
