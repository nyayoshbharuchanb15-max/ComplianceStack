# SPDX-License-Identifier: Apache-2.0
"""Phase execution core: gating → engine → evidence → lineage → event."""
from __future__ import annotations
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from engines import CONTROL_VERSIONS
from engines import (explainability_engine, fairness_engine, privacy_engine,
                     risk_engine, robustness_engine)
from events.fabric import fabric
from graph import lineage
from orchestrator import citations as citations_mod
from orchestrator import ingest as ingest_mod
from orchestrator import scoping
from orchestrator.config import status_base_url
from orchestrator.state_machine import PHASE_NUMBERS, PipelineError, ensure_can_execute
from store import artifacts as artifact_store
from store import evidence as store
from store.hashing import integrity_hash, run_genesis_hash
from certs import issuer as vc_issuer

logger = logging.getLogger("orchestrator.pipeline")

INTAKE_ARTICLES = [
    {"framework": "EU-AI-ACT", "article": "Art. 11", "title": "Technical documentation"},
    {"framework": "GDPR", "article": "Art. 30", "title": "Records of processing activities"},
    {"framework": "ISO-42001", "article": "Clause 7.5", "title": "Documented information"},
    {"framework": "NIST-AI-RMF", "article": "MAP 1.1", "title": "Context and risk identification"},
]

CERTIFICATION_ARTICLES = [
    {"framework": "ISO-42001", "article": "Clause 9.1", "title": "Monitoring, measurement, analysis and evaluation"},
    {"framework": "EU-AI-ACT", "article": "Art. 43", "title": "Conformity assessment"},
]

MONITORING_ARTICLES = [
    {"framework": "EU-AI-ACT", "article": "Art. 72", "title": "Post-market monitoring"},
    {"framework": "ISO-42001", "article": "Clause 9.1", "title": "Monitoring, measurement, analysis and evaluation"},
    {"framework": "NIST-AI-RMF", "article": "MEASURE 3.3", "title": "Ongoing monitoring"},
]

ALL_TRIGGER_TYPES = ["model_version_change", "dataset_revision", "policy_update",
                     "critical_incident", "drift_threshold_breach"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _persist_phase(run: dict, phase_key: str, status: str, inputs: dict,
                         outputs: dict, articles: list[dict], blockers: list[dict],
                         actor: str, prev_hash: str) -> dict:
    run_id = run["run_id"]
    control_version = CONTROL_VERSIONS[phase_key]

    # Build article-level citations against the submitted evidence artifacts
    # AND document-level gap findings (which specific sections of each doc
    # are missing/partial against sub-articles).
    persist_citations, cited_artifacts, missing_artifacts, document_gaps = \
        await citations_mod.build_phase_citations(run_id, phase_key, outputs, blockers)

    # Escalate blocker-severity document gaps into phase blockers.
    from engines.gap_analysis import rollup_phase_blockers
    doc_gap_blockers = rollup_phase_blockers(document_gaps, phase_key)
    if doc_gap_blockers:
        blockers = list(blockers) + doc_gap_blockers
        if status == "passed":
            status = "blocked"

    outputs = {**outputs,
               "citedArtifacts": cited_artifacts,
               "missingArtifacts": missing_artifacts,
               "documentGaps": document_gaps,
               "documentGapSummary": _gap_summary(document_gaps),
               "articleCitations": [
                   {"expectedType": c["expectedType"],
                    "framework": c["framework"], "article": c["article"],
                    "control": c["control"], "verdict": c["verdict"],
                    "artifactId": c.get("artifactId"), "note": c.get("note")}
                   for c in persist_citations]}

    ih = integrity_hash(run_id, phase_key, control_version, inputs, outputs, prev_hash)
    meta = await store.insert_phase_result(
        run_id, phase_key, PHASE_NUMBERS[phase_key], status, inputs, outputs,
        articles, blockers, control_version, ih, prev_hash, actor=actor)
    await artifact_store.insert_citations(run_id, phase_key, persist_citations)
    await artifact_store.insert_phase_gaps(run_id, phase_key, document_gaps)
    await lineage.record_phase(
        run_id, phase_key, PHASE_NUMBERS[phase_key], status, meta["result_id"],
        meta["evidence_id"], ih, control_version, articles, blockers)
    if status == "blocked":
        await store.update_run_status(run_id, "blocked")
        await lineage.set_run_status(run_id, "blocked")
    await fabric.publish_phase_event(
        run_id, phase_key, status, ih, extra={"evidenceId": meta["evidence_id"]})
    return {
        "runId": run_id, "phase": phase_key, "phaseNumber": PHASE_NUMBERS[phase_key],
        "status": status, "controlVersion": control_version, "integrityHash": ih,
        "prevHash": prev_hash, "evidenceId": meta["evidence_id"],
        "legalMappings": articles, "blockers": blockers, "outputs": outputs,
        "citedArtifacts": cited_artifacts, "missingArtifacts": missing_artifacts,
        "documentGaps": document_gaps,
        "completedAt": meta["created_at"],
    }


def _gap_summary(gaps: list[dict]) -> dict:
    """Aggregate counts of {present, partial, gap} findings by severity."""
    counts = {"present": 0, "partial": 0, "gap": 0,
              "blockerGaps": 0, "warningGaps": 0}
    for g in gaps:
        v = g.get("verdict")
        s = g.get("severity")
        if v in counts:
            counts[v] += 1
        if v == "gap":
            if s == "blocker":
                counts["blockerGaps"] += 1
            elif s == "warning":
                counts["warningGaps"] += 1
    return counts


async def execute_intake(inputs: dict, actor: str,
                         reaudit_of: Optional[str] = None,
                         trigger: Optional[dict] = None) -> dict:
    activities = []
    for act in inputs.get("processingActivities", []):
        activities.append({**act, "activityId": act.get("activityId") or str(uuid.uuid4())})
    context = {
        "modelId": inputs["modelId"],
        "modelVersion": inputs["modelVersion"],
        "ownerTeam": inputs.get("ownerTeam", ""),
        "deploymentContext": inputs.get("deploymentContext", {}),
        "processingActivities": activities,
        "datasets": inputs.get("datasets", []),
    }
    run_id = await store.create_run(inputs["modelId"], inputs["modelVersion"], context,
                                    reaudit_of=reaudit_of, trigger=trigger)
    await lineage.record_intake(run_id, inputs["modelId"], inputs["modelVersion"],
                                activities, context["datasets"], reaudit_of=reaudit_of)

    # Persist any evidence artifacts submitted with the intake payload so that
    # subsequent phase engines can cite them under specific regulatory articles.
    # Artifacts may include inline base64 content (`contentBase64`) — if so
    # the ingest module extracts text and runs gap analysis; otherwise they
    # are stored as descriptors.
    submitted_artifacts: list[dict] = []
    for art in inputs.get("evidenceArtifacts", []) or []:
        meta = {k: v for k, v in art.items() if k != "contentBase64"}
        b64 = art.get("contentBase64")
        if b64:
            stored = await ingest_mod.ingest_artifact_base64(
                run_id, meta, b64, submitted_by=actor)
        else:
            stored = await ingest_mod.ingest_artifact_descriptor(
                run_id, meta, submitted_by=actor)
        submitted_artifacts.append(stored)

    outputs = {
        "modelId": inputs["modelId"],
        "modelVersion": inputs["modelVersion"],
        "registeredActivities": [a["activityId"] for a in activities],
        "registeredDatasets": [d["datasetId"] for d in context["datasets"]],
        "contextSummary": {
            "sector": context["deploymentContext"].get("sector", ""),
            "regions": context["deploymentContext"].get("regions", []),
            "autonomyLevel": context["deploymentContext"].get("autonomyLevel", "assistive"),
            "activityCount": len(activities),
            "datasetCount": len(context["datasets"]),
            "artifactCount": len(submitted_artifacts),
        },
        "registeredArtifacts": submitted_artifacts,
    }
    run = {"run_id": run_id, "status": "in_progress", "context": context}
    return await _persist_phase(run, "intake", "passed", inputs, outputs,
                                INTAKE_ARTICLES, [], actor, run_genesis_hash(run_id))


async def execute_phase(run_id: str, phase_key: str, inputs: dict, actor: str,
                        supersedes: Optional[str] = None) -> dict:
    run = await store.get_run(run_id)
    if not run:
        raise PipelineError("RUN_NOT_FOUND", f"Run {run_id} does not exist", status_code=404)
    results = await store.get_phase_results(run_id)
    ensure_can_execute(run, results, phase_key)
    context = run["context"]
    prev_hash = results[-1]["integrity_hash"] if results else run_genesis_hash(run_id)

    context_updates: dict[str, Any] = {}
    post_status: Optional[str] = None

    if phase_key == "scope":
        outputs = scoping.build_scope_map(context)
        articles = [{"framework": e["framework"], "article": e["article"],
                     "title": e["title"]} for e in outputs["scopeMap"]]
        blockers: list[dict] = []
        context_updates["frameworks"] = outputs["frameworks"]
        await lineage.record_scope_mapping(run_id, run["model_id"], outputs["scopeMap"])

    elif phase_key == "risk":
        result = risk_engine.classify(inputs.get("riskInputs", {}))
        articles, blockers = result.pop("_articles"), result.pop("_blockers")
        outputs = result
        context_updates["riskTier"] = outputs["riskTier"]

    elif phase_key == "data_protection":
        result = privacy_engine.assess(context, inputs.get("dataProtection", {}))
        articles, blockers = result.pop("_articles"), result.pop("_blockers")
        outputs = result

    elif phase_key == "fairness":
        result = fairness_engine.evaluate(
            inputs.get("datasetSample", []), inputs.get("sensitiveFeatures", []),
            inputs.get("fairnessThreshold", 0.8))
        articles, blockers = result.pop("_articles"), result.pop("_blockers")
        outputs = result

    elif phase_key == "robustness":
        result = robustness_engine.test(
            inputs.get("testSuites", []), inputs.get("securityControls", {}))
        articles, blockers = result.pop("_articles"), result.pop("_blockers")
        outputs = result

    elif phase_key == "explainability":
        result = explainability_engine.verify(
            context.get("riskTier", "minimal"), inputs.get("oversight", {}),
            inputs.get("explainability", {}))
        articles, blockers = result.pop("_articles"), result.pop("_blockers")
        outputs = result

    elif phase_key == "certification":
        outputs = await _assemble_certificate(run, results, inputs, supersedes)
        articles, blockers = CERTIFICATION_ARTICLES, []
        post_status = "certified"

    elif phase_key == "monitoring":
        monitors = inputs.get("monitors", {})
        config = {
            "driftThreshold": monitors.get("driftThreshold", 0.2),
            "fairnessDriftThreshold": monitors.get("fairnessDriftThreshold", 0.1),
            "reauditTriggers": monitors.get("reauditTriggers") or ALL_TRIGGER_TYPES,
        }
        config_id = await store.insert_monitoring_config(run_id, run["model_id"], config)
        outputs = {"monitoringConfigId": config_id,
                   "armedTriggers": config["reauditTriggers"],
                   "eventStream": "governance:reaudit"}
        articles, blockers = MONITORING_ARTICLES, []
        post_status = "monitoring_active"

    else:
        raise PipelineError("UNKNOWN_PHASE", f"Unknown phase '{phase_key}'", status_code=400)

    envelope = await _persist_phase(run, phase_key, "blocked" if blockers else "passed",
                                    inputs, outputs, articles, blockers, actor, prev_hash)
    if context_updates and not blockers:
        context.update(context_updates)
        await store.update_run_context(run_id, context)
    if post_status and not blockers:
        await store.update_run_status(run_id, post_status)
        await lineage.set_run_status(run_id, post_status)
    return envelope


async def _assemble_certificate(run: dict, results: list[dict], inputs: dict,
                                supersedes: Optional[str]) -> dict:
    credential = vc_issuer.build_credential(
        run, results, inputs.get("issuer", {}), inputs.get("validityDays", 365),
        status_base_url(), previous_credential=supersedes)
    signed = await vc_issuer.sign_credential(credential)
    checks = vc_issuer.verify_credential(signed)
    if not (checks["signatureValid"] and checks["schemaValid"]):
        raise PipelineError("SIGNING_FAILED",
                            f"Credential failed post-signing verification: {checks}",
                            status_code=500)
    anchor = vc_issuer.anchor_hash(signed)
    expires_at = datetime.fromisoformat(signed["validUntil"])
    await store.insert_certificate(
        signed["id"], run["run_id"], run["model_id"], signed, anchor,
        signed["proof"]["verificationMethod"], expires_at, supersedes=supersedes)
    await lineage.record_certificate(run["run_id"], signed["id"])
    if supersedes:
        await lineage.set_certificate_status(supersedes, "superseded")
    return {
        "certificateId": signed["id"],
        "credential": signed,
        "anchorHash": anchor,
        "verification": {"verified": True,
                         "verificationMethod": signed["proof"]["verificationMethod"],
                         "cryptosuite": signed["proof"]["cryptosuite"]},
    }
