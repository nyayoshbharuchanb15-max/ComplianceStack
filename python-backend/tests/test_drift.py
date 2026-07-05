# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Drift Detection (Phase 9) — Evidently AI Integration
"""

from __future__ import annotations
from typing import Any

import pytest

from models.schemas import (
    DriftDetectionConfig,
    FeatureDriftConfig,
    EmbeddingDriftConfig,
    DriftMetric,
    DriftStatus,
)
from services.drift_detector import (
    detect_drift,
    _infer_features,
    _compute_overall_status,
    _fallback_report,
)


class TestFeatureInference:
    def test_returns_numeric_columns(self):
        data = [
            {"a": 1, "b": "str", "c": 3.0},
            {"a": 2, "b": "str2", "c": 4.0},
        ]
        features = _infer_features(data)
        assert "a" in features
        assert "c" in features
        assert "b" not in features

    def test_empty_data_returns_empty_list(self):
        assert _infer_features([]) == []


class TestComputeOverallStatus:
    def test_no_metrics_is_stable(self):
        status, compliant = _compute_overall_status([])
        assert status == DriftStatus.stable
        assert compliant is True

    def test_no_drift_is_stable(self):
        metrics = [
            DriftMetric(feature="a", driftScore=0.05, threshold=0.1, drifted=False),
            DriftMetric(feature="b", driftScore=0.03, threshold=0.1, drifted=False),
        ]
        status, compliant = _compute_overall_status(metrics)
        assert status == DriftStatus.stable
        assert compliant is True

    def test_low_drift_rate_is_warning(self):
        drifted_count = 2
        total = 15
        metrics = [
            DriftMetric(feature=f"f{i}", driftScore=0.15 if i < drifted_count else 0.03, threshold=0.1, drifted=i < drifted_count)
            for i in range(total)
        ]
        status, compliant = _compute_overall_status(metrics)
        assert status == DriftStatus.warning
        assert compliant is True

    def test_high_drift_rate_is_critical(self):
        metrics = [
            DriftMetric(feature=f"f{i}", driftScore=0.5 if i < 4 else 0.03, threshold=0.1, drifted=i < 4)
            for i in range(10)
        ]
        status, compliant = _compute_overall_status(metrics)
        assert status == DriftStatus.critical
        assert compliant is False

    def test_boundary_30_percent_drift_rate(self):
        metrics = [
            DriftMetric(feature=f"f{i}", driftScore=0.5, threshold=0.1, drifted=i < 4)
            for i in range(13)
        ]
        status, compliant = _compute_overall_status(metrics)
        assert status == DriftStatus.critical
        assert compliant is False

    def test_boundary_10_percent_drift_rate(self):
        metrics = [
            DriftMetric(feature=f"f{i}", driftScore=0.5, threshold=0.1, drifted=i < 2)
            for i in range(19)
        ]
        status, compliant = _compute_overall_status(metrics)
        assert status == DriftStatus.warning
        assert compliant is True


class TestFallbackReport:
    @pytest.mark.asyncio
    async def test_returns_stable_report(self):
        report = _fallback_report("test-model", 0.1, "evidently not available")
        assert report.modelId == "test-model"
        assert report.overallDriftStatus == DriftStatus.stable
        assert report.compliant is True
        assert len(report.metrics) == 1
        assert report.metrics[0].feature == "evidently_unavailable"

    @pytest.mark.asyncio
    async def test_includes_regulatory_mappings(self):
        report = _fallback_report("test-model", 0.1, "test")
        assert any("EU AI Act Art. 15" in a for a in report.mappedArticles)
        assert "ISO/IEC 42001:2023 Clause 9.1" in report.iso42001Clause


class TestDetectDriftFallback:
    @pytest.mark.asyncio
    async def test_detect_drift_returns_report(self):
        ref = [
            {"feature_a": 1.0, "feature_b": 2.0},
            {"feature_a": 1.1, "feature_b": 2.1},
        ]
        prod = [
            {"feature_a": 2.0, "feature_b": 3.0},
            {"feature_a": 2.1, "feature_b": 3.1},
        ]
        report = await detect_drift(
            model_id="test-model",
            reference_data=ref,
            production_data=prod,
            features=["feature_a", "feature_b"],
        )
        assert report.modelId == "test-model"
        assert isinstance(report.metrics, list)

    @pytest.mark.asyncio
    async def test_empty_datasets_return_fallback(self):
        report = await detect_drift(
            model_id="test-model",
            reference_data=[],
            production_data=[],
            features=["x"],
        )
        assert report.metrics[0].feature == "evidently_unavailable"

    @pytest.mark.asyncio
    async def test_regulatory_mappings_present(self):
        ref = [{"x": 1.0}, {"x": 2.0}]
        prod = [{"x": 1.5}, {"x": 2.5}]
        report = await detect_drift("test-model", ref, prod, features=["x"])
        assert any("EU AI Act Art. 15" in a for a in report.mappedArticles)
        assert "ISO/IEC 42001:2023 Clause 9.1" in report.iso42001Clause

    @pytest.mark.asyncio
    async def test_feature_inference_when_none_given(self):
        ref = [{"a": 1.0, "b": 2.0, "label": "ok"}]
        prod = [{"a": 1.5, "b": 2.5, "label": "ok"}]
        report = await detect_drift("test-model", ref, prod)
        assert report.modelId == "test-model"

    @pytest.mark.asyncio
    async def test_config_is_accepted(self):
        ref = [{"x": 1.0}, {"x": 2.0}]
        prod = [{"x": 1.5}, {"x": 2.5}]
        config = DriftDetectionConfig(
            features=[FeatureDriftConfig(feature="x", stattest="ks", threshold=0.05)],
            default_stattest="ks",
            drift_threshold=0.05,
        )
        report = await detect_drift("test-model", ref, prod, config=config)
        assert report.modelId == "test-model"

    @pytest.mark.asyncio
    async def test_embedding_config_accepted(self):
        ref = [{"emb_0": 0.1, "emb_1": 0.2}, {"emb_0": 0.3, "emb_1": 0.4}]
        prod = [{"emb_0": 0.5, "emb_1": 0.6}, {"emb_0": 0.7, "emb_1": 0.8}]
        config = DriftDetectionConfig(
            embeddings=[EmbeddingDriftConfig(embedding_name="test_emb", columns=["emb_0", "emb_1"])],
        )
        report = await detect_drift(
            "test-model", ref, prod,
            features=["emb_0", "emb_1"],
            config=config,
        )
        assert report.modelId == "test-model"


class TestDriftDetectionConfigValidation:
    def test_feature_drift_config_defaults(self):
        cfg = FeatureDriftConfig(feature="x")
        assert cfg.stattest is None
        assert cfg.threshold is None

    def test_feature_drift_config_with_values(self):
        cfg = FeatureDriftConfig(feature="x", stattest="jensenshannon", threshold=0.05)
        assert cfg.stattest == "jensenshannon"
        assert cfg.threshold == 0.05

    def test_embedding_drift_config(self):
        cfg = EmbeddingDriftConfig(embedding_name="emb", columns=["a", "b", "c"])
        assert cfg.embedding_name == "emb"
        assert cfg.columns == ["a", "b", "c"]

    def test_drift_detection_config_full(self):
        cfg = DriftDetectionConfig(
            features=[
                FeatureDriftConfig(feature="x", stattest="ks", threshold=0.1),
                FeatureDriftConfig(feature="y"),
            ],
            embeddings=[EmbeddingDriftConfig(embedding_name="z", columns=["z0", "z1"])],
            default_stattest="wasserstein",
            drift_threshold=0.05,
        )
        assert len(cfg.features) == 2
        assert len(cfg.embeddings) == 1
        assert cfg.default_stattest == "wasserstein"
        assert cfg.drift_threshold == 0.05

    def test_drift_detection_config_defaults(self):
        cfg = DriftDetectionConfig()
        assert cfg.features is None
        assert cfg.embeddings is None
        assert cfg.default_stattest == "ks"
        assert cfg.drift_threshold == 0.1


class TestDriftMetricSchema:
    def test_drifted_metric(self):
        m = DriftMetric(feature="x", driftScore=0.5, threshold=0.1, drifted=True)
        assert m.drifted is True
        assert m.driftScore == 0.5

    def test_stable_metric(self):
        m = DriftMetric(feature="y", driftScore=0.02, threshold=0.1, drifted=False)
        assert m.drifted is False
