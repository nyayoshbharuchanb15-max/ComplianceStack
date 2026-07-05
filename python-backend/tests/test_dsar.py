# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: DSAR (GDPR Art. 15–17) — Data Subject Access & Right to Erasure
"""

from __future__ import annotations
import uuid

import pytest

from models.schemas import (
    DSARRequest,
    DSARResponse,
    ErasureStoreStatus,
    ErasureProof,
)
from services.erasure_chain import ErasureChain, access_data_subject_records


class TestDSARRequestValidation:
    def test_access_request_defaults(self):
        req = DSARRequest(
            modelId="test-model",
            dataSubjectId="user-123",
            dataSubjectEmail="user@example.com",
        )
        assert req.requestType == "access"
        assert req.requestDetails == ""

    def test_erasure_request(self):
        req = DSARRequest(
            modelId="test-model",
            dataSubjectId="user-123",
            dataSubjectEmail="user@example.com",
            requestType="erasure",
            requestDetails="Please delete all my data",
        )
        assert req.requestType == "erasure"
        assert "delete" in req.requestDetails

    def test_rectification_request_type(self):
        req = DSARRequest(
            modelId="test-model",
            dataSubjectId="user-456",
            dataSubjectEmail="user2@example.com",
            requestType="rectification",
        )
        assert req.requestType == "rectification"


class TestErasureStoreStatus:
    def test_completed_status(self):
        s = ErasureStoreStatus(
            store="postgresql",
            status="completed",
            recordsDeleted=42,
        )
        assert s.store == "postgresql"
        assert s.recordsDeleted == 42
        assert s.error is None

    def test_failed_status(self):
        s = ErasureStoreStatus(
            store="neo4j",
            status="failed",
            recordsDeleted=0,
            error="Connection refused",
        )
        assert s.status == "failed"
        assert s.error == "Connection refused"

    def test_skipped_status(self):
        s = ErasureStoreStatus(
            store="redis",
            status="skipped",
            recordsDeleted=0,
            error="Redis not connected",
        )
        assert s.status == "skipped"


class TestErasureProof:
    def test_proof_fields(self):
        proof = ErasureProof(
            leafHash="abc123",
            merkleRoot="def456",
            proof=[{"position": "right", "hash": "xyz789"}],
        )
        assert proof.leafHash == "abc123"
        assert proof.merkleRoot == "def456"
        assert len(proof.proof) == 1


class TestDSARResponse:
    def test_minimal_response(self):
        resp = DSARResponse(
            modelId="test-model",
            dataSubjectId="user-1",
            requestType="erasure",
            requestId=str(uuid.uuid4()),
            compliant=True,
            stores=[
                ErasureStoreStatus(
                    store="postgresql", status="completed", recordsDeleted=10,
                ),
            ],
        )
        assert resp.compliant is True
        assert len(resp.stores) == 1
        assert resp.erasureProof is None
        assert resp.erasureCertificate is None

    def test_full_response(self):
        proof = ErasureProof(
            leafHash="a", merkleRoot="b",
            proof=[{"position": "left", "hash": "c"}],
        )
        resp = DSARResponse(
            modelId="test-model",
            dataSubjectId="user-2",
            requestType="erasure",
            requestId=str(uuid.uuid4()),
            compliant=False,
            stores=[
                ErasureStoreStatus(store="pg", status="completed", recordsDeleted=5),
                ErasureStoreStatus(store="neo4j", status="failed", error="timeout"),
            ],
            erasureProof=proof,
        )
        assert resp.compliant is False
        assert resp.erasureProof is not None
        assert resp.erasureProof.merkleRoot == "b"

    def test_regulatory_mappings(self):
        resp = DSARResponse(
            modelId="test",
            dataSubjectId="u1",
            requestType="access",
            requestId=str(uuid.uuid4()),
            compliant=True,
            stores=[],
        )
        assert any("GDPR Art. 15" in a for a in resp.mappedArticles)
        assert any("GDPR Art. 17" in a for a in resp.mappedArticles)
        assert "ISO/IEC 42001:2023" in resp.iso42001Clause


class TestErasureChain:
    @pytest.mark.asyncio
    async def test_chain_creates_audit_records(self):
        chain = ErasureChain("test-model", "user-1", str(uuid.uuid4()))
        chain._audit_step("test:step", {"info": "test"})
        chain._audit_step("test:step2", {"info": "test2"})
        assert len(chain.audit_chain.hashes) == 2

    @pytest.mark.asyncio
    async def test_chain_builds_merkle_tree(self):
        chain = ErasureChain("test-model", "user-1", str(uuid.uuid4()))
        chain._audit_step("pg:delete", {"deleted": 5})
        chain._audit_step("neo4j:delete", {"deleted": 1})
        tree = chain.audit_chain.build_merkle_tree()
        assert len(tree.root) == 64  # SHA-256 hex length
        assert tree.root != "00" * 32

    @pytest.mark.asyncio
    async def test_build_erasure_proof(self):
        chain = ErasureChain("test-model", "user-1", str(uuid.uuid4()))
        chain._audit_step("step0", {"n": 0})
        chain._audit_step("step1", {"n": 1})
        proof = chain.build_erasure_proof(leaf_index=0)
        assert isinstance(proof, ErasureProof)
        assert len(proof.merkleRoot) == 64
        assert len(proof.proof) >= 1

    @pytest.mark.asyncio
    async def test_erasure_certificate_issued(self):
        chain = ErasureChain("test-model", "user-1", str(uuid.uuid4()))
        chain._audit_step("pg:delete", {"deleted": 5})
        chain.store_statuses.append(
            ErasureStoreStatus(store="pg", status="completed", recordsDeleted=5)
        )
        vc = chain.build_erasure_certificate()
        assert vc is not None
        assert vc.credentialSubject["modelId"] == "test-model"
        assert vc.credentialSubject["dataSubjectId"] == "user-1"
        assert "merkleRoot" in vc.credentialSubject
        assert len(vc.proof.proofValue) > 0  # signed

    @pytest.mark.asyncio
    async def test_no_certificate_without_audit(self):
        chain = ErasureChain("test-model", "user-1", str(uuid.uuid4()))
        vc = chain.build_erasure_certificate()
        assert vc is None

    @pytest.mark.asyncio
    async def test_run_with_no_stores_connected(self):
        chain = ErasureChain("test-model", "user-1", str(uuid.uuid4()))
        statuses, audit = await chain.run()
        assert len(statuses) == 3
        stores = {s.store: s for s in statuses}
        assert stores["postgresql"].status == "completed"
        assert stores["neo4j"].status == "skipped"
        assert stores["redis"].status == "skipped"
        assert audit is not None
        assert len(audit.hashes) >= 3  # one per store

    @pytest.mark.asyncio
    async def test_merkle_root_changes_with_different_data(self, monkeypatch):
        async def fake_delete(table):
            return 5

        chain1 = ErasureChain("model-a", "user-1", str(uuid.uuid4()))
        chain2 = ErasureChain("model-b", "user-2", str(uuid.uuid4()))
        chain1._audit_step("pg:delete", {"deleted": 5})
        chain2._audit_step("pg:delete", {"deleted": 10})
        root1 = chain1.audit_chain.build_merkle_tree().root
        root2 = chain2.audit_chain.build_merkle_tree().root
        assert root1 != root2


class TestAccessDataSubjectRecords:
    @pytest.mark.asyncio
    async def test_access_returns_report_structure(self):
        records = await access_data_subject_records(
            model_id="test-model",
            data_subject_id="user-1",
            dsar_request_id=str(uuid.uuid4()),
        )
        assert records["modelId"] == "test-model"
        assert records["dataSubjectId"] == "user-1"
        assert "stores" in records
        assert isinstance(records["stores"], dict)

    @pytest.mark.asyncio
    async def test_access_includes_timestamp(self):
        records = await access_data_subject_records(
            model_id="test-model",
            data_subject_id="user-1",
            dsar_request_id=str(uuid.uuid4()),
        )
        assert "accessDate" in records
        assert records["accessDate"].endswith("Z") or "+" in records["accessDate"]
