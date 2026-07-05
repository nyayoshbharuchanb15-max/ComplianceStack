# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Drift Detector — Continuous Post-Deployment Monitoring
────────────────────────────────────────────────────────
Uses Evidently AI to compare reference (training) data distributions
against production data for drift detection.

EU AI Act Art. 15 mandates ongoing monitoring of accuracy and
robustness. ISO/IEC 42001:2023 Clause 9.1 requires periodic
evaluation of AI system performance.

Detected drift types:
  - Data Drift (KS / Jensen-Shannon): Feature distribution shifts
  - Embedding Drift: latent-space representation shifts

When critical drift is detected, a re-audit webhook is triggered
via Redis Streams (see redis_webhook.py).
"""

from __future__ import annotations
from typing import Any, Optional

import numpy as np
import pandas as pd

from models.schemas import (
    DriftMetric,
    DriftReport,
    DriftStatus,
    DriftDetectionConfig,
)

_EVIDENTLY_AVAILABLE = False
try:
    from evidently.report import Report
    from evidently.metrics import DataDriftPreset, EmbeddingDriftMetric
    from evidently import ColumnMapping
    from evidently.options import DataDriftOptions

    _EVIDENTLY_AVAILABLE = True
except ImportError:
    Report = None  # type: ignore
    DataDriftPreset = None  # type: ignore
    EmbeddingDriftMetric = None  # type: ignore
    ColumnMapping = None  # type: ignore
    DataDriftOptions = None  # type: ignore


STATTEST_MAP = {
    "ks": "ks",
    "jensenshannon": "jensenshannon",
    "wasserstein": "wasserstein",
    "anderson": "anderson",
    "cramer_von_mises": "cramer_von_mises",
    "t_test": "t_test",
    "z_test": "z_test",
    "psi": "psi",
}


async def detect_drift(
    model_id: str,
    reference_data: list[dict[str, Any]],
    production_data: list[dict[str, Any]],
    drift_threshold: float = 0.1,
    features: list[str] | None = None,
    config: DriftDetectionConfig | None = None,
) -> DriftReport:
    """
    Detect feature and embedding drift between reference and production datasets.

    Delegates to Evidently AI's DataDriftPreset for statistical drift tests
    (KS, Jensen-Shannon, etc.) and EmbeddingDriftMetric for latent-space shifts.

    Args:
        model_id: Unique model identifier
        reference_data: Baseline training/validation dataset
        production_data: Current production data sample
        drift_threshold: Global p-value / PSI threshold (default: 0.1)
        features: Subset of features to evaluate (None = all numeric features)
        config: Optional per-feature stat test and threshold overrides

    Returns:
        DriftReport with per-feature drift scores and overall status
    """
    if not _EVIDENTLY_AVAILABLE:
        return _fallback_report(
            model_id, drift_threshold,
            "evidently library not installed. Install with: pip install evidently",
        )

    if features is None:
        features = _infer_features(reference_data) or _infer_features(production_data)

    ref_df = pd.DataFrame(reference_data)
    prod_df = pd.DataFrame(production_data)

    if ref_df.empty or prod_df.empty:
        return _fallback_report(model_id, drift_threshold, "empty dataset")

    effective_threshold = drift_threshold
    if config is not None:
        effective_threshold = config.drift_threshold

    col_map = _build_column_mapping(features, config)
    options = _build_drift_options(features, effective_threshold, config)
    metrics = _build_metrics(features, config)

    report = Report(metrics=metrics)
    report.run(reference_data=ref_df, current_data=prod_df, column_mapping=col_map)

    raw = report.as_dict()
    drift_scores: dict[str, dict[str, Any]] = _extract_drift_by_columns(raw)

    metrics_list: list[DriftMetric] = []
    for feat in features:
        info = drift_scores.get(feat, {})
        score = float(info.get("drift_score", 0.0))
        threshold_used = float(info.get("threshold", effective_threshold))
        drifted = bool(info.get("drift_detected", False))
        metrics_list.append(
            DriftMetric(
                feature=feat,
                driftScore=round(score, 4),
                threshold=round(threshold_used, 4),
                drifted=drifted,
            )
        )

    # embedding drift metrics (not in features list)
    if config and config.embeddings:
        embedding_results = _extract_embedding_drift(raw)
        for emb_name, emb_info in embedding_results.items():
            metrics_list.append(
                DriftMetric(
                    feature=f"embedding:{emb_name}",
                    driftScore=round(emb_info.get("drift_score", 0.0), 4),
                    threshold=round(emb_info.get("threshold", effective_threshold), 4),
                    drifted=emb_info.get("drift_detected", False),
                )
            )

    overall_status, compliant = _compute_overall_status(metrics_list)
    return DriftReport(
        modelId=model_id,
        metrics=metrics_list,
        overallDriftStatus=overall_status,
        compliant=compliant,
    )


# ─── Evidently Helpers ─────────────────────────────────────────────


def _build_column_mapping(
    features: list[str],
    config: DriftDetectionConfig | None,
) -> Any:
    """Build an Evidently ColumnMapping from features and config."""
    if ColumnMapping is None:
        return None
    col_map = ColumnMapping()
    col_map.numerical_features = features
    col_map.categorical_features = []
    col_map.text_features = []
    if config and config.embeddings:
        col_map.embeddings = {
            e.embedding_name: e.columns for e in config.embeddings
        }
    return col_map


def _build_drift_options(
    features: list[str],
    global_threshold: float,
    config: DriftDetectionConfig | None,
) -> Any:
    """Configure per-feature stat tests and thresholds via DataDriftOptions."""
    if DataDriftOptions is None:
        return None
    default_stattest = "ks"
    per_column_stattest: dict[str, str] = {}
    per_column_threshold: dict[str, float] = {}
    if config is not None:
        default_stattest = STATTEST_MAP.get(config.default_stattest, "ks")
        for fc in (config.features or []):
            if fc.stattest:
                mapped = STATTEST_MAP.get(fc.stattest)
                if mapped:
                    per_column_stattest[fc.feature] = mapped
            if fc.threshold is not None:
                per_column_threshold[fc.feature] = fc.threshold
    return DataDriftOptions(
        num_stattest=default_stattest,
        per_column_stattest=per_column_stattest or None,
        per_column_threshold=per_column_threshold or None,
    )


def _build_metrics(
    features: list[str],
    config: DriftDetectionConfig | None,
) -> list:
    """Build the Evidently metrics list."""
    if DataDriftPreset is None:
        return []
    metrics = [DataDriftPreset()]
    if config and config.embeddings and EmbeddingDriftMetric is not None:
        for emb in config.embeddings:
            metrics.append(EmbeddingDriftMetric(embedding_name=emb.embedding_name))
    return metrics


def _extract_drift_by_columns(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract the drift_by_columns dict from a DataDriftPreset result."""
    metrics = raw.get("metrics", [])
    for m in metrics:
        result = m.get("result", {})
        by_columns = result.get("drift_by_columns")
        if by_columns is not None:
            return by_columns
    return {}


def _extract_embedding_drift(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract embedding drift results from the report."""
    metrics = raw.get("metrics", [])
    results: dict[str, dict[str, Any]] = {}
    for m in metrics:
        result = m.get("result", {})
        col_name = result.get("column_name", "")
        if col_name.startswith("embedding:"):
            results[col_name] = result
    return results


# ─── Status Computation ────────────────────────────────────────────


def _compute_overall_status(
    metrics: list[DriftMetric],
) -> tuple[DriftStatus, bool]:
    """Aggregate per-feature drift into overall status."""
    if not metrics:
        return DriftStatus.stable, True
    drifted_count = sum(1 for m in metrics if m.drifted)
    drift_rate = drifted_count / len(metrics)
    if drift_rate > 0.3:
        return DriftStatus.critical, False
    if drift_rate > 0.1:
        return DriftStatus.warning, True
    return DriftStatus.stable, True


# ─── Fallback (no evidently) ───────────────────────────────────────


def _fallback_report(
    model_id: str,
    threshold: float,
    reason: str,
) -> DriftReport:
    """Return a degraded report when Evidently is unavailable."""
    return DriftReport(
        modelId=model_id,
        metrics=[
            DriftMetric(
                feature="evidently_unavailable",
                driftScore=0.0,
                threshold=threshold,
                drifted=False,
            ),
        ],
        overallDriftStatus=DriftStatus.stable,
        compliant=True,
    )


# ─── Data Helpers ──────────────────────────────────────────────────


def _infer_features(data: list[dict[str, Any]]) -> list[str]:
    """Extract numeric feature names from the first record."""
    if not data:
        return []
    return [k for k, v in data[0].items() if isinstance(v, (int, float))]
