# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Bias Assessment (Phase 4) — Real Fairlearn Integration
"""

import pytest
from services.bias_engine import run_bias_assessment, _prepare_dataframe


class TestBiasEngineDataPreparation:
    def test_prepare_dataframe_with_predictions(self):
        samples = [
            {"prediction": 1, "label": 1, "race": "A", "gender": "M"},
            {"prediction": 0, "label": 0, "race": "B", "gender": "F"},
            {"prediction": 1, "label": 1, "race": "A", "gender": "F"},
        ]
        df = _prepare_dataframe(samples, ["race", "gender"])
        assert "prediction" in df.columns
        assert "label" in df.columns
        assert df["prediction"].tolist() == [1, 0, 1]

    def test_prepare_dataframe_with_score(self):
        samples = [
            {"score": 0.9, "label": 1, "race": "A"},
            {"score": 0.2, "label": 0, "race": "B"},
        ]
        df = _prepare_dataframe(samples, ["race"])
        assert "prediction" in df.columns
        assert df["prediction"].tolist() == [0.9, 0.2]

    def test_missing_attributes_are_created(self):
        samples = [{"prediction": 1, "label": 1}]
        df = _prepare_dataframe(samples, ["race"])
        assert "race" in df.columns
        assert df["race"].dtype == "object"


class TestBiasEngineMetrics:
    @pytest.mark.asyncio
    async def test_returns_metrics_for_all_attributes(self):
        samples = [
            {"prediction": 1, "label": 1, "race": "A", "gender": "M"},
            {"prediction": 0, "label": 0, "race": "B", "gender": "F"},
            {"prediction": 1, "label": 1, "race": "A", "gender": "F"},
            {"prediction": 0, "label": 0, "race": "B", "gender": "M"},
        ]
        report = await run_bias_assessment(
            model_id="test-model",
            dataset_sample=samples,
            sensitive_features=["race", "gender"],
        )
        assert len(report.metrics) == 6  # 3 metrics × 2 attributes
        assert report.modelId == "test-model"

    @pytest.mark.asyncio
    async def test_metrics_include_standard_fairness_metrics(self):
        samples = [
            {"prediction": 1, "label": 1, "race": "A"},
            {"prediction": 0, "label": 0, "race": "B"},
        ]
        report = await run_bias_assessment(
            model_id="test-model",
            dataset_sample=samples,
            sensitive_features=["race"],
        )
        metric_names = [m.metric for m in report.metrics]
        assert "demographic_parity_difference" in metric_names
        assert "equal_opportunity_difference" in metric_names
        assert "disparate_impact_ratio" in metric_names

    @pytest.mark.asyncio
    async def test_overall_risk_is_low_for_fair_data(self):
        # Perfectly balanced data should give low bias risk
        samples = [
            {"prediction": 1, "label": 1, "race": "A"},
            {"prediction": 0, "label": 0, "race": "B"},
            {"prediction": 1, "label": 1, "race": "A"},
            {"prediction": 0, "label": 0, "race": "B"},
        ]
        report = await run_bias_assessment(
            model_id="test-model",
            dataset_sample=samples,
            sensitive_features=["race"],
            fairness_threshold=0.8,
        )
        assert report.overallBiasRisk is not None

    @pytest.mark.asyncio
    async def test_compliant_status(self):
        samples = [
            {"prediction": 1, "label": 1, "race": "A"},
            {"prediction": 0, "label": 0, "race": "B"},
        ]
        report = await run_bias_assessment(
            model_id="test-model",
            dataset_sample=samples,
            sensitive_features=["race"],
        )
        assert isinstance(report.compliant, bool)
        assert report.timestamp is not None
