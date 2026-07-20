# SPDX-License-Identifier: Apache-2.0
"""FastAPI routes — one route per phase + reaudit + verification + events."""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from certs import issuer as vc_issuer
from events.fabric import fabric
from graph import lineage
from orchestrator import ingest as ingest_mod
from orchestrator import pipeline, reaudit
from orchestrator.auth import issue_token, require_scope
from orchestrator.state_machine import PipelineError
from store import artifacts as artifact_store
from store import evidence as store

router = APIRouter(prefix="/api/v1")


def _pipeline_error(exc: PipelineError) -> HTTPException:
    return HTTPException(status_code=exc.status_code,
                         detail={"code": exc.code, "message": exc.message})


# ─── Auth ────────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    clientId: str
    clientSecret: str


@router.post("/auth/token")
async def token(req: TokenRequest):
    return issue_token(req.clientId, req.clientSecret)


# ─── Phase request models (contracts: AUDIT_PIPELINE.md) ─────────

class DeploymentContext(BaseModel):
    sector: str = "other"
    regions: list[str] = Field(default_factory=list)
    autonomyLevel: str = "assistive"
    description: Optional[str] = None


class ProcessingActivity(BaseModel):
    name: str
    purpose: str
    dataCategories: list[str] = Field(default_factory=list)
    dataSubjects: list[str] = Field(default_factory=list)
    crossBorder: bool = False
    specialCategories: list[str] = Field(default_factory=list)


class DatasetRef(BaseModel):
    datasetId: str
    version: str = "1"
    containsPersonalData: bool = False
    name: Optional[str] = None
    specialCategories: list[str] = Field(default_factory=list)


class EvidenceArtifact(BaseModel):
    """A document/record submitted as compliance evidence for an audit run."""
    artifactId: Optional[str] = None
    name: str
    type: str = Field(pattern=r"^[a-z_]+$",
                      description="Artifact category, e.g. model_card, dpia, "
                                  "bias_test_output, robustness_test_log, "
                                  "explainability_report, oversight_procedure.")
    uri: Optional[str] = None
    mimeType: Optional[str] = None
    contentSnippet: Optional[str] = None
    contentBase64: Optional[str] = Field(
        None, max_length=20_000_000,
        description="Optional base64-encoded raw file content. When present the "
                    "server extracts text (PDF/CSV/JSON/MD/TXT) and runs the "
                    "document gap analyzer against the extracted text.")
    sha256: Optional[str] = None
    sizeBytes: Optional[int] = None
    tags: list[str] = Field(default_factory=list)


class IntakeRequest(BaseModel):
    modelId: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", max_length=255)
    modelVersion: str
    ownerTeam: str = ""
    deploymentContext: DeploymentContext = Field(default_factory=DeploymentContext)
    processingActivities: list[ProcessingActivity] = Field(default_factory=list)
    datasets: list[DatasetRef] = Field(default_factory=list)
    evidenceArtifacts: list[EvidenceArtifact] = Field(default_factory=list)


class ArtifactUploadRequest(BaseModel):
    artifacts: list[EvidenceArtifact]


class RunScoped(BaseModel):
    runId: str


class RiskInputs(BaseModel):
    usesRealtimeBiometricId: bool = False
    usesSocialScoring: bool = False
    usesManipulativeTechniques: bool = False
    isSafetyComponent: bool = False
    annexIIICategories: list[str] = Field(default_factory=list)
    interactsWithHumans: bool = False
    generatesSyntheticContent: bool = False


class RiskRequest(RunScoped):
    riskInputs: RiskInputs = Field(default_factory=RiskInputs)


class CrossBorderTransfer(BaseModel):
    destination: str
    mechanism: str = "none"


class DataProtectionInputs(BaseModel):
    processesPersonalData: bool = False
    lawfulBasis: str = "none"
    specialCategoryBasis: str = "none"
    dpiaConducted: bool = False
    dpoAppointed: bool = False
    consentMechanism: bool = False
    crossBorderTransfers: list[CrossBorderTransfer] = Field(default_factory=list)
    retentionPeriodDays: Optional[int] = None
    dataMinimisationApplied: bool = False
    privacyByDesign: bool = False


class DataProtectionRequest(RunScoped):
    dataProtection: DataProtectionInputs = Field(default_factory=DataProtectionInputs)


class FairnessRow(BaseModel):
    attributes: dict
    outcome: int = Field(ge=0, le=1)
    label: Optional[int] = Field(default=None, ge=0, le=1)


class FairnessRequest(RunScoped):
    datasetSample: list[FairnessRow]
    sensitiveFeatures: list[str]
    fairnessThreshold: float = Field(default=0.8, ge=0.0, le=1.0)


class SecurityControls(BaseModel):
    inputSanitization: bool = False
    outputFiltering: bool = False
    rateLimiting: bool = False
    adversarialTraining: bool = False
    anomalyMonitoring: bool = False
    accessControl: bool = False


class RobustnessRequest(RunScoped):
    testSuites: list[str]
    securityControls: SecurityControls = Field(default_factory=SecurityControls)


class OversightInputs(BaseModel):
    hasHumanInTheLoop: bool = False
    hasKillSwitch: bool = False
    overrideProcedureDocumented: bool = False
    oversightRoles: list[str] = Field(default_factory=list)


class ExplainabilityInputs(BaseModel):
    method: str = "none"
    userFacingExplanations: bool = False
    decisionLogsRetained: bool = False
    logRetentionDays: Optional[int] = None


class ExplainabilityRequest(RunScoped):
    oversight: OversightInputs = Field(default_factory=OversightInputs)
    explainability: ExplainabilityInputs = Field(default_factory=ExplainabilityInputs)


class IssuerInfo(BaseModel):
    name: str = "AI Governance Authority"
    contact: Optional[str] = None


class CertificationRequest(RunScoped):
    issuer: IssuerInfo = Field(default_factory=IssuerInfo)
    validityDays: int = Field(default=365, ge=1, le=3650)


class Monitors(BaseModel):
    driftThreshold: float = Field(default=0.2, ge=0.0, le=1.0)
    fairnessDriftThreshold: float = Field(default=0.1, ge=0.0, le=1.0)
    reauditTriggers: Optional[list[str]] = None


class MonitoringRequest(RunScoped):
    monitors: Monitors = Field(default_factory=Monitors)


class ReauditTrigger(BaseModel):
    type: str
    detail: str = ""
    datasetId: Optional[str] = None
    newModelVersion: Optional[str] = None
    policyReference: Optional[str] = None
    updatedPhaseInputs: Optional[dict] = None


class ReauditRequest(BaseModel):
    modelId: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", max_length=255)
    trigger: ReauditTrigger


class ObserveMetrics(BaseModel):
    driftScore: Optional[float] = None
    fairnessDelta: Optional[float] = None
    incidentSeverity: Optional[str] = None
    incidentDescription: Optional[str] = None


class ObserveRequest(BaseModel):
    modelId: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", max_length=255)
    metrics: ObserveMetrics = Field(default_factory=ObserveMetrics)


def _inputs(model: BaseModel) -> dict:
    data = model.model_dump(exclude_none=False)
    data.pop("runId", None)
    return data


# ─── Phase routes ────────────────────────────────────────────────

@router.post("/phases/intake")
async def phase_intake(req: IntakeRequest, claims: dict = Depends(require_scope("phase:intake"))):
    try:
        return await pipeline.execute_intake(_inputs(req), claims["sub"])
    except PipelineError as exc:
        raise _pipeline_error(exc)


async def _run_phase(run_id: str, phase_key: str, inputs: dict, claims: dict):
    try:
        return await pipeline.execute_phase(run_id, phase_key, inputs, claims["sub"])
    except PipelineError as exc:
        raise _pipeline_error(exc)


@router.post("/phases/scope")
async def phase_scope(req: RunScoped, claims: dict = Depends(require_scope("phase:scope"))):
    return await _run_phase(req.runId, "scope", _inputs(req), claims)


@router.post("/phases/risk")
async def phase_risk(req: RiskRequest, claims: dict = Depends(require_scope("phase:risk"))):
    return await _run_phase(req.runId, "risk", _inputs(req), claims)


@router.post("/phases/data-protection")
async def phase_data_protection(req: DataProtectionRequest,
                                claims: dict = Depends(require_scope("phase:privacy"))):
    return await _run_phase(req.runId, "data_protection", _inputs(req), claims)


@router.post("/phases/fairness")
async def phase_fairness(req: FairnessRequest,
                         claims: dict = Depends(require_scope("phase:fairness"))):
    return await _run_phase(req.runId, "fairness", _inputs(req), claims)


@router.post("/phases/robustness")
async def phase_robustness(req: RobustnessRequest,
                           claims: dict = Depends(require_scope("phase:robustness"))):
    return await _run_phase(req.runId, "robustness", _inputs(req), claims)


@router.post("/phases/explainability")
async def phase_explainability(req: ExplainabilityRequest,
                               claims: dict = Depends(require_scope("phase:explainability"))):
    return await _run_phase(req.runId, "explainability", _inputs(req), claims)


@router.post("/phases/certification")
async def phase_certification(req: CertificationRequest,
                              claims: dict = Depends(require_scope("phase:certify"))):
    return await _run_phase(req.runId, "certification", _inputs(req), claims)


@router.post("/phases/monitoring")
async def phase_monitoring(req: MonitoringRequest,
                           claims: dict = Depends(require_scope("phase:monitor"))):
    return await _run_phase(req.runId, "monitoring", _inputs(req), claims)


# ─── Reaudit ─────────────────────────────────────────────────────

@router.post("/reaudit")
async def trigger_reaudit(req: ReauditRequest,
                          claims: dict = Depends(require_scope("reaudit:trigger"))):
    try:
        return await reaudit.execute_reaudit(req.modelId, req.trigger.model_dump(), claims["sub"])
    except PipelineError as exc:
        raise _pipeline_error(exc)


# ─── Runs ────────────────────────────────────────────────────────

class RunListQuery(BaseModel):
    modelId: Optional[str] = None
    status: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)


@router.get("/runs")
async def list_runs(modelId: Optional[str] = None,
                    status: Optional[str] = None,
                    limit: int = 50,
                    claims: dict = Depends(require_scope("runs:read"))):
    rows = await store.list_runs(model_id=modelId, status=status,
                                  limit=max(1, min(200, limit)))
    return {"runs": rows}


@router.get("/runs/{run_id}")
async def get_run(run_id: str, claims: dict = Depends(require_scope("runs:read"))):
    run = await store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail={"code": "RUN_NOT_FOUND",
                                                     "message": f"Run {run_id} not found"})
    results = await store.get_phase_results(run_id)
    cert = await store.get_certificate_for_run(run_id)
    citations = await artifact_store.list_citations(run_id)
    arts = await artifact_store.list_artifacts(run_id)
    gaps = await artifact_store.list_phase_gaps(run_id)
    return {
        "runId": run_id, "modelId": run["model_id"], "modelVersion": run["model_version"],
        "status": run["status"], "reauditOf": run.get("reaudit_of"),
        "trigger": run.get("trigger"), "createdAt": run.get("created_at"),
        "updatedAt": run.get("updated_at"),
        "context": run.get("context"),
        "phases": [{"phase": r["phase_key"], "phaseNumber": r["phase_number"],
                    "status": r["status"], "integrityHash": r["integrity_hash"],
                    "prevHash": r["prev_hash"], "evidenceId": r["evidence_id"],
                    "carriedForward": r["carried_forward"],
                    "blockers": r["blocker_reasons"],
                    "outputs": r["outputs"],
                    "legalMappings": r["legal_mappings"],
                    "completedAt": r["created_at"]}
                   for r in results],
        "artifacts": arts,
        "citations": citations,
        "gaps": gaps,
        "certificateId": cert["certificate_id"] if cert else None,
    }


@router.get("/runs/{run_id}/lineage")
async def get_run_lineage(run_id: str, claims: dict = Depends(require_scope("runs:read"))):
    return await lineage.get_run_lineage(run_id)


# ─── Artifacts (per-run evidence documents) ──────────────────────

@router.post("/runs/{run_id}/artifacts")
async def upload_artifacts(run_id: str, req: ArtifactUploadRequest,
                           claims: dict = Depends(require_scope("phase:intake"))):
    """Upload one or more artifact descriptors (JSON body).

    Each artifact may include an optional ``contentBase64`` field. When
    present the server decodes it, computes sha256 over the raw bytes,
    extracts text, and runs the document gap analyzer.
    """
    run = await store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail={
            "code": "RUN_NOT_FOUND", "message": f"Run {run_id} not found"})
    stored: list[dict] = []
    for art in req.artifacts:
        payload = art.model_dump(exclude_none=True)
        b64 = payload.pop("contentBase64", None)
        try:
            if b64:
                stored.append(await ingest_mod.ingest_artifact_base64(
                    run_id, payload, b64, submitted_by=claims["sub"]))
            else:
                stored.append(await ingest_mod.ingest_artifact_descriptor(
                    run_id, payload, submitted_by=claims["sub"]))
        except ValueError as e:
            raise HTTPException(status_code=422, detail={
                "code": "INVALID_ARTIFACT", "message": str(e)})
    return {"runId": run_id, "artifacts": stored}


@router.post("/runs/{run_id}/artifacts/upload")
async def upload_artifact_multipart(
    run_id: str,
    file: UploadFile = File(...),
    type: str = Form(...),
    name: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    uri: Optional[str] = Form(None),
    claims: dict = Depends(require_scope("phase:intake")),
):
    """Upload a real file as an artifact (multipart/form-data).

    The server computes sha256 over the raw bytes, extracts text
    (PDF via pypdf, CSV/JSON/MD/TXT natively), and runs the document gap
    analyzer for the declared artifact ``type``.
    """
    run = await store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail={
            "code": "RUN_NOT_FOUND", "message": f"Run {run_id} not found"})

    if not type or not type.replace("_", "").isalpha():
        raise HTTPException(status_code=422, detail={
            "code": "INVALID_TYPE",
            "message": "type must be a lowercase snake_case artifact category"})

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=422, detail={
            "code": "EMPTY_FILE", "message": "Uploaded file is empty"})
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail={
            "code": "FILE_TOO_LARGE",
            "message": "Artifact exceeds 20 MB limit"})

    meta = {
        "name": name or file.filename or f"upload-{type}",
        "type": type,
        "uri": uri,
        "mimeType": file.content_type or None,
        "tags": [t.strip() for t in (tags or "").split(",") if t.strip()],
    }
    stored = await ingest_mod.ingest_artifact_bytes(
        run_id, meta, content, submitted_by=claims["sub"])
    return {"runId": run_id, "artifact": stored}


@router.get("/runs/{run_id}/artifacts")
async def list_run_artifacts(run_id: str,
                             claims: dict = Depends(require_scope("runs:read"))):
    run = await store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail={
            "code": "RUN_NOT_FOUND", "message": f"Run {run_id} not found"})
    return {"runId": run_id,
            "artifacts": await artifact_store.list_artifacts(run_id),
            "citations": await artifact_store.list_citations(run_id),
            "gaps": await artifact_store.list_phase_gaps(run_id)}


@router.get("/artifacts/{artifact_id}")
async def get_artifact(artifact_id: str,
                        claims: dict = Depends(require_scope("runs:read"))):
    """Return the extracted text + gap findings for one artifact (for preview)."""
    art = await artifact_store.get_artifact_text(artifact_id)
    if not art:
        raise HTTPException(status_code=404, detail={
            "code": "ARTIFACT_NOT_FOUND", "message": f"Artifact {artifact_id} not found"})
    return art


# ─── Certificates ────────────────────────────────────────────────

@router.get("/certificates")
async def list_certificates(modelId: Optional[str] = None,
                            status: Optional[str] = None,
                            limit: int = 50,
                            claims: dict = Depends(require_scope("certs:read"))):
    return {"certificates": await store.list_certificates(
        model_id=modelId, status=status, limit=max(1, min(200, limit)))}

@router.get("/certificates/{certificate_id}")
async def get_certificate(certificate_id: str,
                          claims: dict = Depends(require_scope("certs:read"))):
    cert = await store.get_certificate(certificate_id)
    if not cert:
        raise HTTPException(status_code=404, detail={"code": "CERT_NOT_FOUND",
                                                     "message": "Certificate not found"})
    return cert


@router.get("/certificates/{certificate_id}/verify")
async def verify_certificate(certificate_id: str):
    cert = await store.get_certificate(certificate_id)
    if not cert:
        raise HTTPException(status_code=404, detail={"code": "CERT_NOT_FOUND",
                                                     "message": "Certificate not found"})
    checks = vc_issuer.verify_credential(cert["vc_payload"])
    not_revoked = cert["status"] != "revoked"
    verified = (checks["signatureValid"] and checks["schemaValid"]
                and checks["notExpired"] and not_revoked)
    return {"certificateId": certificate_id, "verified": verified,
            "status": cert["status"], "anchorHash": cert["anchor_hash"],
            "checks": {**checks, "notRevoked": not_revoked}}


@router.get("/certificates/{certificate_id}/status")
async def certificate_status(certificate_id: str):
    cert = await store.get_certificate(certificate_id)
    if not cert:
        raise HTTPException(status_code=404, detail={"code": "CERT_NOT_FOUND",
                                                     "message": "Certificate not found"})
    return {"certificateId": certificate_id, "status": cert["status"],
            "statusPurpose": "revocation",
            "revokedAt": cert.get("revoked_at"),
            "revocationReason": cert.get("revocation_reason"),
            "supersededBy": cert.get("superseded_by")}


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


@router.post("/certificates/{certificate_id}/revoke")
async def revoke_certificate(certificate_id: str, req: RevokeRequest,
                             claims: dict = Depends(require_scope("certs:read"))):
    ok = await store.revoke_certificate(certificate_id, req.reason)
    if not ok:
        raise HTTPException(status_code=404, detail={
            "code": "CERT_NOT_REVOCABLE",
            "message": "Certificate not found or already revoked"})
    await lineage.set_certificate_status(certificate_id, "revoked")
    return {"certificateId": certificate_id, "status": "revoked", "reason": req.reason}


# ─── Monitoring observations ─────────────────────────────────────

@router.post("/monitoring/observe")
async def observe(req: ObserveRequest, claims: dict = Depends(require_scope("phase:monitor"))):
    config = await store.get_active_monitoring(req.modelId)
    if not config:
        raise HTTPException(status_code=404, detail={
            "code": "NO_ACTIVE_MONITORING",
            "message": f"No active monitoring configuration for model '{req.modelId}'"})
    cfg = config["config"]
    m = req.metrics
    trigger_type = None
    detail = ""
    if m.driftScore is not None and m.driftScore > cfg["driftThreshold"]:
        trigger_type, detail = "drift_threshold_breach", \
            f"driftScore {m.driftScore} > threshold {cfg['driftThreshold']}"
    elif m.fairnessDelta is not None and m.fairnessDelta > cfg["fairnessDriftThreshold"]:
        trigger_type, detail = "drift_threshold_breach", \
            f"fairnessDelta {m.fairnessDelta} > threshold {cfg['fairnessDriftThreshold']}"
    elif m.incidentSeverity == "critical":
        trigger_type, detail = "critical_incident", m.incidentDescription or "critical incident reported"

    if not trigger_type or trigger_type not in cfg["reauditTriggers"]:
        return {"triggered": False, "queued": False,
                "reason": "Metrics within thresholds or trigger not armed"}
    event_id = await fabric.publish_reaudit_trigger(
        req.modelId, {"type": trigger_type, "detail": detail})
    return {"triggered": True, "queued": event_id is not None,
            "triggerType": trigger_type, "eventId": event_id,
            "eventStream": "governance:reaudit"}


# ─── Event fabric introspection ──────────────────────────────────

@router.get("/events/recent")
async def recent_events(claims: dict = Depends(require_scope("runs:read"))):
    return {"events": await store.list_events(limit=50)}


@router.get("/events/dead-letter")
async def dead_letter_events(claims: dict = Depends(require_scope("runs:read"))):
    return {"deadLetters": await fabric.read_dead_letters(),
            "ledger": await store.list_events(status="dead_letter", limit=50)}


@router.post("/events/test-dead-letter")
async def test_dead_letter(claims: dict = Depends(require_scope("runs:read"))):
    """Diagnostics: publish a poison event that always fails → must land in the DLQ."""
    import uuid as _uuid
    event_id = await fabric.publish("governance:phase-events", "governance.test.poison",
                                    {"note": "poison test"}, event_id=_uuid.uuid4().hex)
    return {"published": event_id is not None, "eventId": event_id,
            "expectation": "dead-letter after 3 delivery attempts"}
