# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Risk Classification (Phase 1)
"""

import pytest
from routers.risk import _evaluate_risk_tier, _build_rationale
from models.schemas import ClassifyRiskRequest, RiskTier


def make_request(model_type="general_purpose_ai", sector="healthcare", uses_profiling=False):
    return ClassifyRiskRequest(
        modelId="test-model",
        modelType=model_type,
        sector=sector,
        usesProfiling=uses_profiling,
    )


class TestRiskClassification:
    def test_prohibited_tier(self):
        req = make_request(model_type="real_time_biometric")
        tier = _evaluate_risk_tier(req)
        assert tier == RiskTier.prohibited

    def test_high_risk_annex_iii(self):
        req = make_request(sector="employment")
        tier = _evaluate_risk_tier(req)
        assert tier == RiskTier.high

    def test_high_risk_profiling(self):
        req = make_request(model_type="general_purpose_ai", uses_profiling=True)
        tier = _evaluate_risk_tier(req)
        assert tier == RiskTier.high

    def test_limited_risk(self):
        req = make_request(model_type="general_purpose_ai", uses_profiling=False)
        tier = _evaluate_risk_tier(req)
        assert tier == RiskTier.limited

    def test_minimal_risk(self):
        req = make_request(model_type="other", sector="other")
        tier = _evaluate_risk_tier(req)
        assert tier == RiskTier.minimal

    def test_rationale_includes_mappings(self):
        req = make_request(sector="employment")
        rationale = _build_rationale(RiskTier.high, req)
        assert "HIGH-RISK" in rationale
        assert "Annex III" in rationale
        assert "Conformity assessment" in rationale
