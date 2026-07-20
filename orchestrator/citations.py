# SPDX-License-Identifier: Apache-2.0
"""Per-phase expected-artifact ↔ regulatory-article expectation matrix.

For every phase we declare which artifact types SHOULD have been submitted as
evidence, and which regulatory article/control each artifact is testifying
against. This is what turns "the fairness check passed" into "the fairness
check passed BECAUSE bias_test_output.json (sha256:…) was inspected under
EU-AI-ACT Art. 10 and NIST MEASURE 2.2, and no artifact was missing".

Verdict grammar:
    pass    — the artifact exists AND the phase engine also passed the control
    warning — the artifact is present but the engine flagged a soft issue
    fail    — the artifact is present but its contents (or absence of a
              declared property) triggered a blocker
    missing — no artifact of this type was submitted for the run
    present — the artifact exists; used when the engine has no direct verdict
"""
from __future__ import annotations
from typing import Optional

from store import artifacts as artifact_store


# expectedType, framework, article, control
PHASE_EXPECTATIONS: dict[str, list[tuple[str, str, str, str]]] = {
    "intake": [
        ("model_card", "EU-AI-ACT", "Art. 11", "Technical documentation of the AI system"),
        ("ropa_record", "GDPR", "Art. 30", "Records of processing activities"),
        ("risk_assessment", "ISO-42001", "Clause 6.1", "Actions to address risks and opportunities"),
    ],
    "scope": [
        ("model_card", "NIST-AI-RMF", "MAP 1.1", "Context and risk identification"),
    ],
    "risk": [
        ("risk_assessment", "EU-AI-ACT", "Art. 6", "High-risk classification rationale"),
        ("model_card", "EU-AI-ACT", "Annex III", "Intended purpose vs Annex III use cases"),
    ],
    "data_protection": [
        ("dpia", "GDPR", "Art. 35", "Data Protection Impact Assessment"),
        ("data_flow_map", "GDPR", "Art. 30", "Records of processing activities"),
        ("consent_ux_evidence", "GDPR", "Art. 6", "Lawful basis (consent) evidence"),
        ("ropa_record", "DPDP-ACT", "Sec. 8", "Data Fiduciary obligations"),
    ],
    "fairness": [
        ("bias_test_output", "EU-AI-ACT", "Art. 10", "Data and data governance — bias examination"),
        ("fairness_metrics_report", "NIST-AI-RMF", "MEASURE 2.2",
         "Fairness evaluation results"),
        ("dataset_lineage", "EU-AI-ACT", "Art. 10",
         "Representativeness of training/validation data"),
    ],
    "robustness": [
        ("adversarial_test_report", "EU-AI-ACT", "Art. 15",
         "Accuracy, robustness and cybersecurity — adversarial resilience"),
        ("robustness_test_log", "NIST-AI-RMF", "MEASURE 2.7",
         "Security and resilience evaluation"),
        ("security_audit", "ISO-42001", "Clause 8.1.3",
         "AI system development and operations security controls"),
    ],
    "explainability": [
        ("explainability_report", "EU-AI-ACT", "Art. 13",
         "Transparency and provision of information to deployers"),
        ("decision_log_sample", "EU-AI-ACT", "Art. 12",
         "Record-keeping (automatic logging of events)"),
        ("oversight_procedure", "EU-AI-ACT", "Art. 14",
         "Human oversight measures"),
        ("kill_switch_evidence", "EU-AI-ACT", "Art. 14",
         "Intervention / stop capability (Art. 14(4)(e))"),
    ],
    "certification": [
        ("conformity_declaration", "EU-AI-ACT", "Art. 43",
         "Conformity assessment declaration"),
    ],
    "monitoring": [
        ("monitoring_dashboard", "EU-AI-ACT", "Art. 72",
         "Post-market monitoring plan and dashboards"),
        ("incident_report", "ISO-42001", "Clause 9.1",
         "Monitoring, measurement, analysis and evaluation"),
    ],
}


def _default_verdict(phase_key: str, outputs: dict, blockers: list[dict],
                     expected_type: str, artifact_present: bool,
                     framework: str, article: str) -> str:
    """Deterministically map engine outcome + artifact presence → citation verdict."""
    if not artifact_present:
        return "missing"

    # If a blocker was raised on the same framework+article, that artifact fails
    for b in blockers:
        if b.get("framework") == framework and b.get("article") == article:
            return "fail"

    # Phase-specific soft-signal mapping (walk phase findings)
    findings = outputs.get("findings") or []
    for f in findings:
        if f.get("framework") == framework and f.get("article") == article:
            status = f.get("status", "pass")
            if status == "fail":
                return "fail"
            if status == "warning":
                return "warning"
            return "pass"

    # Fairness phase: soft warning if the artifact type is the metrics report but
    # engine's worst DI is still just above threshold (no per-finding rows).
    if phase_key == "fairness":
        wd = outputs.get("worstDisparateImpact")
        thr = outputs.get("threshold", 0.8)
        if wd is not None and wd < thr:
            return "fail"
        return "pass"

    # Robustness: attribute pass/fail by overall score
    if phase_key == "robustness":
        overall = outputs.get("overallResistance")
        if overall is not None:
            if overall < 0.5:
                return "fail"
            if overall < 0.9:
                return "warning"
            return "pass"

    return "present"


async def build_phase_citations(run_id: str, phase_key: str, outputs: dict,
                                blockers: list[dict]) -> tuple[
                                    list[dict], list[dict], list[dict], list[dict]]:
    """Return (citations_for_persist, cited_artifacts, missing_expectations,
    document_gaps).

    - citations_for_persist: rows to insert into governance_phase_citations
    - cited_artifacts: [{artifactId, name, type, sha256, framework, article,
                         control, verdict, gapScore}]  — reflected in the phase outputs
    - missing_expectations: [{expectedType, framework, article, control,
                              reason}]  — reflected in phase outputs
    - document_gaps: [{artifactId, artifactName, artifactType, framework, article,
                        section, verdict, severity, evidenceSpan, note}]  —
                     the diagnostic gap-analysis findings for every cited
                     document, so the UI can answer "what's missing inside
                     the DPIA that we uploaded".
    """
    expectations = PHASE_EXPECTATIONS.get(phase_key, [])
    citations: list[dict] = []
    cited: list[dict] = []
    missing: list[dict] = []
    document_gaps: list[dict] = []

    for expected_type, framework, article, control in expectations:
        arts = await artifact_store.get_artifacts_by_type(run_id, expected_type)
        if arts:
            for a in arts:
                verdict = _default_verdict(phase_key, outputs, blockers,
                                           expected_type, True, framework, article)
                # Merge in gap-analysis signal: if any blocker-severity gap
                # exists in this artifact, force fail; else if warning-severity
                # gap → warning; else present/pass stays.
                worst_gap = _worst_gap_for(a, framework, article)
                if worst_gap == "blocker":
                    verdict = "fail"
                elif worst_gap == "warning" and verdict in ("pass", "present"):
                    verdict = "warning"

                gap_score = a.get("gapScore")
                gap_hint = (f" · gap-score {gap_score:.2f}"
                            if gap_score is not None else "")
                ext_status = a.get("extractionStatus") or "pending"
                note = (f"Inspected {a['name']} (sha256 {a['sha256'][:10]}…) "
                        f"[{ext_status}]{gap_hint}")
                citations.append({
                    "artifactId": a["artifactId"], "expectedType": expected_type,
                    "framework": framework, "article": article,
                    "control": control, "verdict": verdict, "note": note})
                cited.append({
                    "artifactId": a["artifactId"], "name": a["name"],
                    "type": a["type"], "sha256": a["sha256"],
                    "framework": framework, "article": article,
                    "control": control, "verdict": verdict,
                    "extractionStatus": ext_status,
                    "gapScore": gap_score})
                # Emit per-section gap findings for this artifact (deduped
                # across expectations — an artifact is analyzed once).
                for gf in (a.get("gapFindings") or []):
                    if not any(dg["artifactId"] == gf["artifactId"]
                               and dg["section"] == gf["section"]
                               for dg in document_gaps):
                        document_gaps.append({
                            "artifactId": gf["artifactId"],
                            "artifactName": a["name"],
                            "artifactType": expected_type,
                            "framework": gf["framework"],
                            "article": gf["article"],
                            "section": gf["section"],
                            "verdict": gf["verdict"],
                            "severity": gf["severity"],
                            "evidenceSpan": gf.get("evidenceSpan", ""),
                            "note": gf.get("note", ""),
                        })
        else:
            reason = (f"No {expected_type} artifact submitted for run — "
                      f"cannot evidence {framework} {article} ({control}).")
            citations.append({
                "artifactId": None, "expectedType": expected_type,
                "framework": framework, "article": article,
                "control": control, "verdict": "missing", "note": reason})
            missing.append({
                "expectedType": expected_type, "framework": framework,
                "article": article, "control": control, "reason": reason})

    return citations, cited, missing, document_gaps


def _worst_gap_for(artifact: dict, framework: str, article: str) -> Optional[str]:
    """Highest gap severity in this artifact scoped to (framework, article).

    Returns 'blocker' > 'warning' > None. If the gap-analysis flagged a gap
    (not merely partial) for the sub-article we're testing, return that
    severity — so the citation verdict can escalate accordingly.
    """
    worst: Optional[str] = None
    for g in artifact.get("gapFindings") or []:
        if g["verdict"] != "gap":
            continue
        # Match either exact article or a parent article (Art. 35 covers Art. 35(7)(a))
        if g["framework"] != framework:
            continue
        ga = g["article"]
        if not (ga == article or ga.startswith(article + "(") or article.startswith(ga + "(")):
            continue
        if g["severity"] == "blocker":
            return "blocker"
        if g["severity"] == "warning":
            worst = "warning"
    return worst
