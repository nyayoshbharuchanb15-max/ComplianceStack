# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Agent Autonomy Classification (Phase F) — Risk Tier Mapping
"""

from __future__ import annotations
import pytest

from services.agent_autonomy_classifier import (
    classify_autonomy,
    _fallback_classify,
    _map_to_risk_tier,
    _build_rationale,
)
from models.schemas import AutonomyLevel, RiskTier


class TestFallbackClassify:
    def test_self_modify_is_fully_autonomous(self):
        assert _fallback_classify((True, True, True, True, True)) == AutonomyLevel.fully_autonomous

    def test_no_oversight_with_decisions_is_autonomous(self):
        assert _fallback_classify((True, False, False, False, False)) == AutonomyLevel.autonomous

    def test_can_decide_with_oversight_is_supervised(self):
        assert _fallback_classify((True, False, False, False, True)) == AutonomyLevel.supervised

    def test_no_decisions_is_assistive(self):
        assert _fallback_classify((False, False, False, False, False)) == AutonomyLevel.assistive


class TestMapToRiskTier:
    def test_fully_autonomous_is_high(self):
        assert _map_to_risk_tier(AutonomyLevel.fully_autonomous, "single", "assistive") == RiskTier.high

    def test_autonomous_multi_agent_is_high(self):
        assert _map_to_risk_tier(AutonomyLevel.autonomous, "multi_agent", "autonomous") == RiskTier.high

    def test_autonomous_single_is_limited(self):
        assert _map_to_risk_tier(AutonomyLevel.autonomous, "single", "batch") == RiskTier.limited

    def test_supervised_is_limited(self):
        assert _map_to_risk_tier(AutonomyLevel.supervised, "single", "assistive") == RiskTier.limited

    def test_assistive_is_minimal(self):
        assert _map_to_risk_tier(AutonomyLevel.assistive, "single", "assistive") == RiskTier.minimal


class TestBuildRationale:
    def test_basic_rationale(self):
        rationale = _build_rationale(AutonomyLevel.supervised, True, False, False, False, True)
        assert "can make decisions" in rationale
        assert "human oversight is present" in rationale
        assert "supervised" in rationale

    def test_no_oversight_rationale(self):
        rationale = _build_rationale(AutonomyLevel.autonomous, True, True, False, False, False)
        assert "no human oversight" in rationale


class TestClassifyAutonomy:
    @pytest.mark.asyncio
    async def test_assistive_agent(self):
        result = await classify_autonomy(
            model_id="test-model",
            agent_type="single",
            has_human_oversight=True,
            can_make_decisions=False,
            can_modify_environment=False,
            can_delegate_tasks=False,
            can_access_external_apis=False,
            can_self_modify=False,
            deployment_context="assistive",
        )
        assert result.autonomyLevel == AutonomyLevel.assistive
        assert result.riskTier == RiskTier.minimal
        assert result.humanOversightRequired is False
        assert result.compliant is True

    @pytest.mark.asyncio
    async def test_supervised_agent(self):
        result = await classify_autonomy(
            model_id="test-model",
            agent_type="single",
            has_human_oversight=True,
            can_make_decisions=True,
            can_modify_environment=False,
            can_delegate_tasks=False,
            can_access_external_apis=False,
            can_self_modify=False,
            deployment_context="batch",
        )
        assert result.autonomyLevel == AutonomyLevel.supervised
        assert result.riskTier == RiskTier.limited
        assert result.humanOversightRequired is True

    @pytest.mark.asyncio
    async def test_autonomous_agent(self):
        result = await classify_autonomy(
            model_id="test-model",
            agent_type="single",
            has_human_oversight=True,
            can_make_decisions=True,
            can_modify_environment=True,
            can_delegate_tasks=True,
            can_access_external_apis=False,
            can_self_modify=False,
            deployment_context="real_time",
        )
        assert result.autonomyLevel == AutonomyLevel.autonomous
        assert result.compliant is True

    @pytest.mark.asyncio
    async def test_fully_autonomous_blocked(self):
        result = await classify_autonomy(
            model_id="test-model",
            agent_type="multi_agent",
            has_human_oversight=False,
            can_make_decisions=True,
            can_modify_environment=True,
            can_delegate_tasks=True,
            can_access_external_apis=True,
            can_self_modify=True,
            deployment_context="autonomous",
        )
        assert result.autonomyLevel == AutonomyLevel.fully_autonomous
        assert result.riskTier == RiskTier.high
        assert result.compliant is False
        assert len(result.recommendedControls) >= 5

    @pytest.mark.asyncio
    async def test_regulatory_mappings(self):
        result = await classify_autonomy(
            model_id="test-model",
            agent_type="single",
            has_human_oversight=True,
            can_make_decisions=False,
            can_modify_environment=False,
            can_delegate_tasks=False,
            can_access_external_apis=False,
            can_self_modify=False,
            deployment_context="assistive",
        )
        assert any("EU AI Act" in a for a in result.mappedArticles)
        assert "ISO/IEC 42001:2023" in result.iso42001Clause

    @pytest.mark.asyncio
    async def test_controls_by_level(self):
        result = await classify_autonomy(
            model_id="test-model",
            agent_type="single",
            has_human_oversight=False,
            can_make_decisions=True,
            can_modify_environment=True,
            can_delegate_tasks=True,
            can_access_external_apis=True,
            can_self_modify=True,
            deployment_context="autonomous",
        )
        assert len(result.recommendedControls) >= 5
        assert any("BLOCKER" in c for c in result.recommendedControls)
