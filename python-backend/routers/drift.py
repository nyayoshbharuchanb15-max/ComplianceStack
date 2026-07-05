# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Model Drift Monitoring Router — Continuous Post-Deployment Monitoring
───────────────────────────────────────────────────────────────────────
Sets up continuous drift detection using Evidently AI, comparing
reference (training) data against production data.

EU AI Act Art. 15 — High-risk AI systems shall be monitored for
accuracy and robustness throughout their lifecycle.
NIST AI RMF MEASURE 3.3 — Continuous monitoring for changes in
the operational context.
ISO/IEC 42001:2023 Clause 9.1 — The organization shall monitor
the performance of AI systems and take corrective action when
deviations are detected.

Re-Audit Trigger: When critical drift is detected, a webhook event
is published to Redis Streams for automated re-audit.
"""

from fastapi import APIRouter, HTTPException, Request
from models.schemas import MonitorDriftRequest, DriftReport
from services.auth import Scope, require_scope
from services.drift_detector import detect_drift
from services.evidence_store import record_audit_evidence, record_drift_alert, log_audit_event
from services.redis_webhook import webhook_engine

router = APIRouter(prefix="/api/drift", tags=["Drift Monitoring"])


@router.post("/monitor", response_model=DriftReport)
@require_scope(Scope.audit_write)
async def monitor_model_drift(request: MonitorDriftRequest, request_obj: Request):
    """
    Execute drift detection between reference and production data.

    Args:
        modelId: Unique model identifier
        referenceData: Baseline training/validation dataset
        productionData: Current production data sample
        driftThreshold: PSI threshold for flagging drift (default: 0.1)
        features: Feature names to monitor

    Returns:
        DriftReport with per-feature metrics and overall status

    If critical drift is detected, a re-audit event is automatically
    published via Redis Streams (ISO 42001 Clause 9.1.2).
    """
    try:
        report = await detect_drift(
            model_id=request.modelId,
            reference_data=request.referenceData,
            production_data=request.productionData,
            drift_threshold=request.driftThreshold,
            features=request.features,
            config=request.driftConfig,
        )

        # Persist to evidence store
        await record_audit_evidence(
            model_id=request.modelId,
            audit_phase="drift_monitoring",
            payload=report.model_dump(),
        )

        # Log audit trail
        await log_audit_event(
            model_id=request.modelId,
            phase="drift_monitoring",
            action="drift_monitored",
            outcome="success",
            details={"overall_drift_status": report.overallDriftStatus.value},
        )

        # Log individual drift alerts
        for metric in report.metrics:
            if metric.drifted:
                await record_drift_alert(
                    model_id=request.modelId,
                    metric=metric.feature,
                    drift_score=metric.driftScore,
                    threshold=metric.threshold,
                    status=report.overallDriftStatus.value,
                )

        # ── Re-Audit Trigger ──────────────────────────────────
        # ISO 42001 Clause 9.1.2: Nonconformity triggers corrective action
        if report.overallDriftStatus.value == "critical":
            try:
                await webhook_engine.publish_reaudit_event(
                    model_id=request.modelId,
                    reason="critical_drift_detected",
                    triggered_by="drift_monitor",
                    severity="critical",
                    metadata={
                        "features_flagged": [m.feature for m in report.metrics if m.drifted],
                        "overall_drift_score": max(m.driftScore for m in report.metrics) if report.metrics else 0,
                    },
                )
            except Exception:
                # Redis might not be available — log but don't fail the request
                pass

        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Drift monitoring failed: {str(e)}")
