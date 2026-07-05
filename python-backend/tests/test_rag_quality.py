# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: RAG Quality Audit (Phase B) — Retrieval Quality Evaluation
"""

from __future__ import annotations
import pytest

from services.rag_quality_auditor import (
    evaluate_rag_quality,
    _compute_hallucination_rate,
    _compute_attribution_accuracy,
    _compute_relevance,
    _derive_risk,
)
from models.schemas import RAGQualityMetric, RiskLevel


class TestHallucinationRate:
    def test_no_hallucination(self):
        queries = [
            {"hallucinated": False},
            {"hallucinated": False},
        ]
        assert _compute_hallucination_rate(queries) == 0.0

    def test_all_hallucinated(self):
        queries = [
            {"hallucinated": True},
            {"hallucinated": True},
        ]
        assert _compute_hallucination_rate(queries) == 1.0

    def test_empty_queries(self):
        assert _compute_hallucination_rate([]) == 0.10

    def test_mixed(self):
        queries = [
            {"hallucinated": True},
            {"hallucinated": False},
            {"hallucinated": False},
        ]
        assert abs(_compute_hallucination_rate(queries) - 1 / 3) < 0.01


class TestAttributionAccuracy:
    def test_all_correct(self):
        queries = [{"attributionCorrect": True}, {"attributionCorrect": True}]
        assert _compute_attribution_accuracy(queries) == 1.0

    def test_none_correct(self):
        queries = [{"attributionCorrect": False}, {"attributionCorrect": False}]
        assert _compute_attribution_accuracy(queries) == 0.0

    def test_empty_default(self):
        assert _compute_attribution_accuracy([]) == 0.85


class TestRelevance:
    def test_explicit_scores(self):
        queries = [{"relevance_score": 0.9}, {"relevance_score": 0.8}]
        assert abs(_compute_relevance(queries) - 0.85) < 0.01

    def test_no_scores_default(self):
        assert _compute_relevance([]) == 0.80


class TestDeriveRisk:
    def test_low_risk(self):
        metric = RAGQualityMetric(metric="Hallucination Rate", score=0.05, threshold=0.15, passed=True, details="")
        assert _derive_risk(0.9, metric) == RiskLevel.low

    def test_critical_high_hallucination(self):
        metric = RAGQualityMetric(metric="Hallucination Rate", score=0.30, threshold=0.15, passed=False, details="")
        assert _derive_risk(0.9, metric) == RiskLevel.critical

    def test_medium_risk(self):
        metric = RAGQualityMetric(metric="Hallucination Rate", score=0.10, threshold=0.15, passed=True, details="")
        assert _derive_risk(0.6, metric) == RiskLevel.medium


class TestEvaluateRAGQuality:
    @pytest.mark.asyncio
    async def test_basic_evaluation(self):
        queries = [
            {"retrieved_relevant": True, "all_relevant_retrieved": True, "hallucinated": False, "attributionCorrect": True, "relevance_score": 0.9},
            {"retrieved_relevant": True, "all_relevant_retrieved": False, "hallucinated": False, "attributionCorrect": True, "relevance_score": 0.8},
        ]
        report = await evaluate_rag_quality(
            model_id="test-model",
            vector_db_config={"totalSources": 10, "freshSources": 8},
            sample_queries=queries,
            freshness_policy_days=90,
        )
        assert report.modelId == "test-model"
        assert len(report.metrics) == 7
        assert report.retrievalAccuracy >= 0.5

    @pytest.mark.asyncio
    async def test_empty_queries_still_works(self):
        report = await evaluate_rag_quality(
            model_id="test-model",
            vector_db_config={},
            sample_queries=[],
            freshness_policy_days=90,
        )
        assert report.modelId == "test-model"
        assert len(report.metrics) == 7

    @pytest.mark.asyncio
    async def test_regulatory_mappings(self):
        report = await evaluate_rag_quality(
            model_id="test-model",
            vector_db_config={},
            sample_queries=[],
            freshness_policy_days=90,
        )
        assert any("EU AI Act" in a for a in report.mappedArticles)
        assert "ISO/IEC 42001:2023" in report.iso42001Clause
