# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Human Oversight Verification (Phase 3)
"""

import pytest
from unittest.mock import MagicMock
from models.schemas import VerifyHumanOversightRequest, DeploymentContext
from routers.human_oversight import verify_human_oversight


def _make_request_obj(scopes=None):
    """Create a minimal mock Request object that satisfies @require_scope."""
    req = MagicMock()
    req.state.scopes = scopes or ["audit:write"]
    return req


class TestHumanOversight:
    @pytest.mark.asyncio
    async def test_full_oversight_passes(self):
        req = VerifyHumanOversightRequest(
            modelId="test-model",
            hasHumanInTheLoop=True,
            hasKillSwitch=True,
            oversightProcess="Two-person review rule applied",
            deploymentContext=DeploymentContext.real_time,
        )
        result = await verify_human_oversight(req, request_obj=_make_request_obj())
        assert result.compliant is True
        assert result.blocker is False
        assert result.oversightLevel.value == "full"

    @pytest.mark.asyncio
    async def test_missing_kill_switch_triggers_blocker_for_real_time(self):
        req = VerifyHumanOversightRequest(
            modelId="test-model",
            hasHumanInTheLoop=True,
            hasKillSwitch=False,
            deploymentContext=DeploymentContext.real_time,
        )
        result = await verify_human_oversight(req, request_obj=_make_request_obj())
        assert result.blocker is True
        assert result.compliant is False
        assert result.remediation is not None
        assert "BLOCKER" in result.remediation

    @pytest.mark.asyncio
    async def test_missing_kill_switch_no_blocker_for_assistive(self):
        req = VerifyHumanOversightRequest(
            modelId="test-model",
            hasHumanInTheLoop=False,
            hasKillSwitch=False,
            deploymentContext=DeploymentContext.assistive,
        )
        result = await verify_human_oversight(req, request_obj=_make_request_obj())
        assert result.blocker is False

    @pytest.mark.asyncio
    async def test_regulatory_mappings_present(self):
        req = VerifyHumanOversightRequest(
            modelId="test-model",
            hasHumanInTheLoop=True,
            hasKillSwitch=True,
            deploymentContext=DeploymentContext.batch,
        )
        result = await verify_human_oversight(req, request_obj=_make_request_obj())
        assert any("EU AI Act Art. 14" in a for a in result.mappedArticles)
        assert any("GDPR Art. 22" in a for a in result.mappedArticles)
        assert "ISO/IEC 42001:2023 Clause 8.2" in result.iso42001Clause
