# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: ROPA Generation (GDPR Art. 30) — Record of Processing Activities
"""

from __future__ import annotations
import uuid
from unittest.mock import MagicMock

import pytest
from models.schemas import (
    GenerateROPARequest,
    ROPAReport,
    ROPADataSubjectCategory,
    ROPADataCategory,
)
from routers.ropa import generate_ropa


def _make_request_obj(scopes=None):
    """Create a minimal mock Request object that satisfies @require_scope."""
    req = MagicMock()
    req.state.scopes = scopes or ["audit:write"]
    return req


async def _noop_record_audit(**kwargs):
    pass


@pytest.fixture
def mock_record_audit_evidence(monkeypatch):
    monkeypatch.setattr("routers.ropa.record_audit_evidence", _noop_record_audit)
    yield monkeypatch


class TestGenerateROPARequestValidation:
    def test_minimal_request(self):
        req = GenerateROPARequest(
            modelId="test-model",
            controllerName="Acme Corp",
            controllerAddress="123 Main St",
            controllerEmail="dpo@acme.com",
            processingPurposes=["Model training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="employees",
                    description="Current and former employees",
                    retentionPeriod="3 years",
                    erasureMechanism="Automated delete after notice period",
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="performance_data",
                    description="Model performance metrics",
                    retentionPeriod="5 years",
                    erasureMechanism="Archived then deleted",
                    securityMeasures=["Encryption at rest"],
                )
            ],
            recipientCategories=["Cloud provider"],
        )
        assert req.modelId == "test-model"
        assert len(req.dataCategories) == 1

    def test_full_request(self):
        req = GenerateROPARequest(
            modelId="test-model",
            controllerName="Acme Corp",
            controllerRepresentative="John Doe",
            dpoName="Data Protection Officer",
            controllerAddress="123 Main St",
            controllerEmail="dpo@acme.com",
            jointControllers=["Partner Corp"],
            processingPurposes=["Training", "Analytics"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="employees",
                    description="Employees",
                    retentionPeriod="3 years",
                    erasureMechanism="Delete after notice",
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="performance_data",
                    description="Metrics",
                    retentionPeriod="5 years",
                    erasureMechanism="Archived then deleted",
                    securityMeasures=["Encryption"],
                )
            ],
            recipientCategories=["Cloud provider"],
        )
        assert req.controllerRepresentative == "John Doe"
        assert req.dpoName == "Data Protection Officer"
        assert req.jointControllers == ["Partner Corp"]
        assert "Training" in req.processingPurposes
        assert "Analytics" in req.processingPurposes

    def test_special_category_flag(self):
        cat = ROPADataCategory(
            category="health_data",
            description="Medical records",
            specialCategory=True,
            retentionPeriod="10 years",
            erasureMechanism="Archived then destroyed",
            securityMeasures=["Encryption"],
        )
        assert cat.specialCategory is True


class TestROPADataSubjectCategory:
    def test_create_subject_category(self):
        cat = ROPADataSubjectCategory(
            category="children",
            description="Minors under 16",
            retentionPeriod="Until age 18",
            erasureMechanism="Deleted when user turns 18",
        )
        assert cat.category == "children"
        assert cat.retentionPeriod == "Until age 18"


class TestROPADataCategory:
    def test_default_special_category(self):
        cat = ROPADataCategory(
            category="usage_data",
            description="Anonymous usage statistics",
            retentionPeriod="2 years",
            erasureMechanism="Automated purge",
            securityMeasures=["Pseudonymization"],
        )
        assert cat.specialCategory is False

    def test_security_measures_default(self):
        cat = ROPADataCategory(
            category="log_data",
            description="System logs",
            retentionPeriod="90 days",
            erasureMechanism="Rotated after 90 days",
            securityMeasures=[],
        )
        assert cat.securityMeasures == []


class TestGenerateROPAResponse:
    @pytest.mark.asyncio
    async def test_returns_ropa_report(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test-model",
            controllerName="Acme Corp",
            controllerAddress="123 Main St",
            controllerEmail="dpo@acme.com",
            processingPurposes=["Model training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="employees",
                    description="Employees",
                    retentionPeriod="3 years",
                    erasureMechanism="Delete after notice",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="performance_data",
                    description="Metrics",
                    retentionPeriod="5 years",
                    erasureMechanism="Archived then deleted",
                    securityMeasures=["Encryption"],
                )
            ],
            recipientCategories=["Cloud provider"],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert isinstance(report, ROPAReport)
        assert report.modelId == "test-model"
        assert report.controllerName == "Acme Corp"

    @pytest.mark.asyncio
    async def test_ropa_id_is_generated(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test-model",
            controllerName="Acme Corp",
            controllerAddress="123 Main St",
            controllerEmail="dpo@acme.com",
            processingPurposes=["Training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="employees",
                    description="Employees",
                    retentionPeriod="3 years",
                    erasureMechanism="Auto-delete",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="perf",
                    description="Metrics",
                    retentionPeriod="5 years",
                    erasureMechanism="Archive",
                    securityMeasures=["Encryption"],
                )
            ],
            recipientCategories=["Provider"],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert report.ropaId is not None
        assert report.ropaId.startswith("urn:uuid:") or len(report.ropaId) == 36

    @pytest.mark.asyncio
    async def test_all_fields_passed_through(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="model-123",
            controllerName="Big Corp",
            controllerRepresentative="Alice",
            dpoName="Bob",
            controllerAddress="456 Oak Ave",
            controllerEmail="dpo@bigcorp.com",
            jointControllers=["Joint Inc"],
            processingPurposes=["Training", "Inference"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="users",
                    description="Platform users",
                    retentionPeriod="3 years",
                    erasureMechanism="Account deletion",
                    securityMeasures=[],
                    specialCategory=False,
                ),
            ],
            dataCategories=[
                ROPADataCategory(
                    category="email",
                    description="Email addresses",
                    retentionPeriod="3 years",
                    erasureMechanism="Deleted on account close",
                    securityMeasures=["Encryption"],
                ),
            ],
            recipientCategories=["AWS", "Datadog"],
            crossBorderTransfer=True,
            thirdCountries=["US", "Singapore"],
            transferSafeguards=["SCCs"],
            retentionScheduleDescription="Per category policy",
            securityMeasures=["TLS", "RBAC", "Encryption"],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert report.controllerRepresentative == "Alice"
        assert report.dpoName == "Bob"
        assert report.jointControllers == ["Joint Inc"]
        assert report.crossBorderTransfer is True
        assert "US" in report.thirdCountries
        assert "SCCs" in report.transferSafeguards
        assert "TLS" in report.securityMeasures

    @pytest.mark.asyncio
    async def test_compliant_with_all_requirements(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test",
            controllerName="Compliant Corp",
            controllerAddress="Addr",
            controllerEmail="e@e.com",
            processingPurposes=["Training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="users",
                    description="Users",
                    retentionPeriod="3y",
                    erasureMechanism="Del",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="scores",
                    description="Prediction scores",
                    retentionPeriod="5 years",
                    erasureMechanism="Archived",
                    securityMeasures=["Encryption"],
                ),
            ],
            recipientCategories=["Cloud"],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert report.compliant is True

    @pytest.mark.asyncio
    async def test_non_compliant_when_retention_missing(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test",
            controllerName="NonCompliant Corp",
            controllerAddress="Addr",
            controllerEmail="e@e.com",
            processingPurposes=["Training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="users",
                    description="Users",
                    retentionPeriod="3y",
                    erasureMechanism="Del",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="scores",
                    description="Prediction scores",
                    retentionPeriod="",
                    erasureMechanism="Archived",
                    securityMeasures=["Encryption"],
                ),
            ],
            recipientCategories=["Cloud"],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert report.compliant is False

    @pytest.mark.asyncio
    async def test_non_compliant_when_no_controller_name(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test",
            controllerName="",
            controllerAddress="Addr",
            controllerEmail="e@e.com",
            processingPurposes=["Training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="users",
                    description="Users",
                    retentionPeriod="3y",
                    erasureMechanism="Del",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="scores",
                    description="Scores",
                    retentionPeriod="5y",
                    erasureMechanism="Archive",
                    securityMeasures=["Enc"],
                ),
            ],
            recipientCategories=["Cloud"],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert report.compliant is False

    @pytest.mark.asyncio
    async def test_cross_border_without_safeguards_non_compliant(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test",
            controllerName="Corp",
            controllerAddress="Addr",
            controllerEmail="e@e.com",
            processingPurposes=["Training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="users",
                    description="Users",
                    retentionPeriod="3y",
                    erasureMechanism="Del",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="scores",
                    description="Scores",
                    retentionPeriod="5y",
                    erasureMechanism="Archive",
                    securityMeasures=["Enc"],
                ),
            ],
            recipientCategories=["Cloud"],
            crossBorderTransfer=True,
            transferSafeguards=[],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert report.compliant is False

    @pytest.mark.asyncio
    async def test_regulatory_mappings_present(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test",
            controllerName="Corp",
            controllerAddress="Addr",
            controllerEmail="e@e.com",
            processingPurposes=["Training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="users",
                    description="Users",
                    retentionPeriod="3y",
                    erasureMechanism="Del",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="scores",
                    description="Scores",
                    retentionPeriod="5y",
                    erasureMechanism="Archive",
                    securityMeasures=["Enc"],
                ),
            ],
            recipientCategories=["Cloud"],
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert any("GDPR Art. 30" in a for a in report.mappedArticles)
        assert "ISO/IEC 42001:2023 Clause 7.5" in report.iso42001Clause

    @pytest.mark.asyncio
    async def test_retention_schedule_fallback(self, mock_record_audit_evidence):
        req = GenerateROPARequest(
            modelId="test",
            controllerName="Corp",
            controllerAddress="Addr",
            controllerEmail="e@e.com",
            processingPurposes=["Training"],
            dataSubjectCategories=[
                ROPADataSubjectCategory(
                    category="users",
                    description="Users",
                    retentionPeriod="3y",
                    erasureMechanism="Del",
                    securityMeasures=[],
                    specialCategory=False,
                )
            ],
            dataCategories=[
                ROPADataCategory(
                    category="scores",
                    description="Scores",
                    retentionPeriod="5y",
                    erasureMechanism="Archive",
                    securityMeasures=["Enc"],
                ),
            ],
            recipientCategories=["Cloud"],
            retentionScheduleDescription="",
        )
        report = await generate_ropa(req, request_obj=_make_request_obj())
        assert report.retentionScheduleDescription == "Retention periods are defined per data category above."