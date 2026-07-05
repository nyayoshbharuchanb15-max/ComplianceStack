# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Erasure Chain — Cascading Data Erasure with Merkle Audit Trail
───────────────────────────────────────────────────────────────
Implements the right to erasure (GDPR Art. 17) across all data
stores with cryptographic audit proof.

The erasure cascades through:
  1. PostgreSQL — Clears audit_evidence, certificates, drift_alerts, pii_redactions
  2. Neo4j      — Removes model nodes and provenance relationships
  3. Redis      — Deletes webhook streams and cached keys

Each erasure step is recorded in a Merkle audit chain providing
tamper-evident proof that the erasure was executed.

GDPR Art. 17 — Right to erasure ('right to be forgotten').
GDPR Art. 5(1)(e) — Storage limitation: personal data shall be kept
no longer than necessary.
ISO/IEC 42001:2023 Clause 7.5 — Documented information integrity
via cryptographic audit trail.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Optional

from db.postgres import pg_client
from db.neo4j_client import neo4j_client
from services.redis_webhook import webhook_engine
from services.merkle_audit import AuditChain
from services.crypto_signer import crypto_signer
from models.verifiable_credential import VCIssuer, VerifiableCredential
from models.schemas import ErasureStoreStatus, ErasureProof


class ErasureChain:
    """
    Cascading erasure executor with cryptographic audit proof.

    Each store is erased sequentially. Every erasure action is
    recorded in a Merkle audit chain. The final Merkle root and
    per-leaf proofs are returned for external verification.
    """

    def __init__(self, model_id: str, data_subject_id: str, request_id: str):
        self.model_id = model_id
        self.data_subject_id = data_subject_id
        self.request_id = request_id
        self.audit_chain = AuditChain()
        self.store_statuses: list[ErasureStoreStatus] = []

    async def run(self) -> tuple[list[ErasureStoreStatus], Optional[AuditChain]]:
        """
        Execute erasure across all registered data stores.

        Returns:
            Tuple of (per-store statuses, AuditChain with Merkle proof)
        """
        await self._erase_postgresql()
        await self._erase_neo4j()
        await self._erase_redis()

        return self.store_statuses, self.audit_chain

    async def _erase_postgresql(self) -> None:
        """Erase all records related to the model from PostgreSQL."""
        tables = [
            "pii_redactions",
            "drift_alerts",
            "certificates",
            "audit_evidence",
        ]
        total = 0
        errors: list[str] = []
        for table in tables:
            try:
                deleted = await self._delete_from_table(table)
                total += deleted
                self._audit_step(f"postgresql:{table}", {"deleted": deleted})
            except Exception as e:
                errors.append(f"{table}: {e}")
                self._audit_step(f"postgresql:{table}", {"error": str(e)})

        self.store_statuses.append(
            ErasureStoreStatus(
                store="postgresql",
                status="failed" if errors else "completed",
                recordsDeleted=total,
                error="; ".join(errors) if errors else None,
            )
        )

    async def _delete_from_table(self, table: str) -> int:
        """Delete rows for model_id from a table, return count."""
        if pg_client.pool is None:
            return 0
        async with pg_client.pool.acquire() as conn:
            result = await conn.execute(
                f"DELETE FROM {table} WHERE model_id = $1",
                self.model_id,
            )
            # asyncpg's execute returns a tag like "DELETE 5"
            parts = result.split()
            return int(parts[-1]) if len(parts) == 2 else 0

    async def _erase_neo4j(self) -> None:
        """Remove model nodes and all provenance relationships from Neo4j."""
        if neo4j_client.driver is None:
            self.store_statuses.append(
                ErasureStoreStatus(
                    store="neo4j", status="skipped", recordsDeleted=0,
                    error="Neo4j not connected",
                )
            )
            return
        try:
            async with neo4j_client.driver.session() as session:
                result = await session.run(
                    "MATCH (m:Model {modelId: $model_id}) "
                    "OPTIONAL MATCH (m)-[r]-() "
                    "DELETE r, m "
                    "RETURN count(m) AS models_deleted",
                    model_id=self.model_id,
                )
                record = await result.single()
                deleted = record["models_deleted"] if record else 0
            self._audit_step("neo4j:model", {"deleted": deleted})
            self.store_statuses.append(
                ErasureStoreStatus(
                    store="neo4j", status="completed", recordsDeleted=deleted,
                )
            )
        except Exception as e:
            self._audit_step("neo4j:model", {"error": str(e)})
            self.store_statuses.append(
                ErasureStoreStatus(
                    store="neo4j", status="failed", recordsDeleted=0,
                    error=str(e),
                )
            )

    async def _erase_redis(self) -> None:
        """Remove model-related keys and streams from Redis."""
        if webhook_engine.client is None:
            self.store_statuses.append(
                ErasureStoreStatus(
                    store="redis", status="skipped", recordsDeleted=0,
                    error="Redis not connected",
                )
            )
            return
        try:
            redis = webhook_engine.client
            pattern = f"*{self.model_id}*"
            keys = await redis.keys(pattern)
            deleted = len(keys)
            if keys:
                await redis.delete(*keys)
            # Also delete the reaudit stream entries for this model
            stream = "reaudit:requests"
            stream_entries = await redis.xlen(stream)
            if stream_entries > 0:
                # Trim the stream; consumer group cleanup is handled separately
                await redis.xtrim(stream, 0)
            self._audit_step("redis:keys", {"deleted": deleted, "stream_trimmed": bool(stream_entries)})
            self.store_statuses.append(
                ErasureStoreStatus(
                    store="redis", status="completed", recordsDeleted=deleted,
                )
            )
        except Exception as e:
            self._audit_step("redis:keys", {"error": str(e)})
            self.store_statuses.append(
                ErasureStoreStatus(
                    store="redis", status="failed", recordsDeleted=0,
                    error=str(e),
                )
            )

    def _audit_step(self, step: str, details: dict[str, Any]) -> str:
        """Record an erasure step in the Merkle audit chain."""
        record = {
            "step": step,
            "model_id": self.model_id,
            "data_subject_id": self.data_subject_id,
            "request_id": self.request_id,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self.audit_chain.append(record)

    def build_erasure_proof(self, leaf_index: int = 0) -> ErasureProof:
        """Build a Merkle proof for a specific erasure step."""
        tree = self.audit_chain.build_merkle_tree()
        leaf_hash = self.audit_chain.hashes[leaf_index]
        proof = tree.get_proof(leaf_index)
        return ErasureProof(
            leafHash=leaf_hash,
            merkleRoot=tree.root,
            proof=proof,
        )

    def build_erasure_certificate(self) -> Optional[VerifiableCredential]:
        """Issue a W3C Verifiable Credential attesting the erasure."""
        if not self.audit_chain.hashes:
            return None
        tree = self.audit_chain.build_merkle_tree()
        subject_data = {
            "modelId": self.model_id,
            "dataSubjectId": self.data_subject_id,
            "requestId": self.request_id,
            "erasureDate": datetime.now(timezone.utc).isoformat(),
            "stores": [
                {"store": s.store, "status": s.status, "recordsDeleted": s.recordsDeleted}
                for s in self.store_statuses
            ],
            "merkleRoot": tree.root,
            "stepCount": len(self.audit_chain.hashes),
            "framework": "GDPR Art. 17 Erasure — AI Governance MCP Server",
        }
        issuer = VCIssuer(
            issuer_id="did:web:governance.internal:issuers:erasure",
            issuer_name="AI Governance Erasure Authority",
        )
        vc = issuer.issue(subject_data=subject_data, valid_days=365)
        canonical_payload = vc.to_signing_payload()
        signature = crypto_signer.sign_payload(canonical_payload)
        verification_method = crypto_signer.verification_method
        vc.proof.proofValue = signature
        vc.proof.verificationMethod = verification_method
        vc.proof.created = datetime.now(timezone.utc).isoformat()
        return vc


# ─── Data Subject Access Request helper ────────────────────────────


async def access_data_subject_records(
    model_id: str,
    data_subject_id: str,
    dsar_request_id: str,
) -> dict[str, Any]:
    """
    Retrieve all records related to a data subject across stores.

    Returns a consolidated report of all stored data related to
    the subject. This fulfills GDPR Art. 15 (Right of Access).
    """
    records: dict[str, Any] = {
        "modelId": model_id,
        "dataSubjectId": data_subject_id,
        "requestId": dsar_request_id,
        "accessDate": datetime.now(timezone.utc).isoformat(),
        "stores": {},
    }
    if pg_client.pool is not None:
        async with pg_client.pool.acquire() as conn:
            evidence = await conn.fetch(
                "SELECT evidence_id, audit_phase, evidence_type, created_at "
                "FROM audit_evidence WHERE model_id = $1 "
                "ORDER BY created_at DESC LIMIT 100",
                model_id,
            )
            records["stores"]["postgresql"] = {
                "evidence_records": [dict(r) for r in evidence],
            }
    if neo4j_client.driver is not None:
        async with neo4j_client.driver.session() as session:
            graph = await session.run(
                "MATCH (m:Model {modelId: $model_id}) "
                "OPTIONAL MATCH (m)-[r]-(related) "
                "RETURN m, collect(r) AS relationships",
                model_id=model_id,
            )
            node = await graph.single()
            records["stores"]["neo4j"] = {
                "model_found": node is not None,
            }
    if webhook_engine.client is not None:
        redis = webhook_engine.client
        keys = await redis.keys(f"*{model_id}*")
        records["stores"]["redis"] = {
            "cached_keys": len(keys),
        }
    return records
