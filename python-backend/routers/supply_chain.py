# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Supply Chain Audit Router — Neo4j Provenance Graph
────────────────────────────────────────────────────
Audits the AI model's supply chain by querying the Neo4j provenance
graph for data lineage, IP clearance, and third-party dependencies.

EU AI Act Art. 10 — Data governance requires that training data
be examined for biases and gaps.
EU AI Act Art. 12 — Technical documentation must include the
development methodology and data sources.
ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain traceability.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from models.schemas import (
    AuditSupplyChainRequest,
    ProvenanceReport,
    ProvenanceRecord,
    RiskLevel,
    SupplyChainNodeType,
)
from services.evidence_store import record_audit_evidence, log_audit_event
from services.data_discovery import populate_provenance_graph
from services.auth import Scope, require_scope
from db.neo4j_client import neo4j_client


class DiscoveryRequest(BaseModel):
    modelId: str
    modelSearchPaths: list[str] = []
    dataSearchPaths: list[str] = []

router = APIRouter(prefix="/api/supply-chain", tags=["Supply Chain"])


@router.post("/discover")
@require_scope(Scope.audit_write)
async def discover_supply_chain(request: DiscoveryRequest, request_obj: Request):
    """
    Automatically discover model artifacts and datasets on the
    filesystem and populate the Neo4j provenance graph.

    EU AI Act Art. 10 — Data governance requires documented data provenance.
    ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain traceability.
    """
    try:
        result = await populate_provenance_graph(
            model_id=request.modelId,
            model_search_paths=request.modelSearchPaths or None,
            data_search_paths=request.dataSearchPaths or None,
        )

        # Add regulatory mappings to discovery result
        result["mappedArticles"] = [
            "EU AI Act Art. 10 (Data Governance)",
            "EU AI Act Art. 12 (Technical Documentation)",
            "ISO/IEC 42001:2023 Clause 7.4.3 (Supply Chain Traceability)",
            "NIST AI RMF MAP 2.2 (Data Provenance)",
            "GDPR Art. 5(1)(d) (Accuracy of Data)",
            "DPDP Act 2023 Sec. 7 (Duties of Data Fiduciary)",
        ]

        # Persist discovery results as evidence
        await record_audit_evidence(
            model_id=request.modelId,
            audit_phase="supply_chain_discovery",
            payload=result,
        )

        # Log audit trail
        await log_audit_event(
            model_id=request.modelId,
            phase="supply_chain_discovery",
            action="supply_chain_discovered",
            outcome="success",
            details={"models_found": len(result.get("discoveredModels", []))},
        )

        return result
    except Exception as e:
        await log_audit_event(
            model_id=request.modelId,
            phase="supply_chain_discovery",
            action="supply_chain_discovered",
            outcome="failure",
            details={"error": str(e)},
        )
        raise HTTPException(status_code=500, detail=f"Data discovery failed: {str(e)}")


@router.post("/audit", response_model=ProvenanceReport)
@require_scope(Scope.audit_write)
async def audit_supply_chain(request: AuditSupplyChainRequest, request_obj: Request):
    """
    Audit the AI model's software and data supply chain.

    Traces all dependencies, datasets, and third-party components
    through the Neo4j provenance graph, checking:
      1. IP clearance for all components
      2. License compatibility
      3. Data lineage completeness
      4. Transitive dependency risk

    Returns a ProvenanceReport with graph data and overall risk.
    """
    try:
        # Ensure the model node exists in the graph
        await neo4j_client.add_model_node(
            request.modelId,
            {"name": request.modelId, "auditStatus": "in_progress"},
        )

        # Retrieve provenance graph
        graph_data = await neo4j_client.get_provenance_graph(
            request.modelId, deep=request.deepScan
        )

        # Check IP clearance
        ip_result = await neo4j_client.check_ip_clearance(request.modelId)

        # Build provenance records from graph data
        records: list[ProvenanceRecord] = []
        for item in graph_data:
            node = item.get("node", item.get("model", {}))
            if not node:
                continue
            records.append(
                ProvenanceRecord(
                    nodeId=node.get("modelId", node.get("datasetId", "unknown")),
                    type=_infer_node_type(node),
                    name=node.get("name", "Unknown"),
                    version=node.get("version", "0.0.0"),
                    origin=node.get("origin", "unknown"),
                    license=node.get("license", "unknown"),
                    ipCleared=node.get("ipCleared", False),
                )
            )

        # Determine overall risk
        all_cleared = ip_result.get("allCleared", False)
        risk = RiskLevel.low if all_cleared else (
            RiskLevel.critical if ip_result.get("totalComponents", 0) > 0 and not all_cleared
            else RiskLevel.medium
        )

        report = ProvenanceReport(
            modelId=request.modelId,
            graph=records,
            supplyChainRisk=risk,
            ipClearance=all_cleared,
            compliant=all_cleared and risk != RiskLevel.critical,
        )

        # Persist to evidence store (ISO 42001 Clause 7.5)
        await record_audit_evidence(
            model_id=request.modelId,
            audit_phase="supply_chain_audit",
            payload=report.model_dump(),
        )

        # Log audit trail
        await log_audit_event(
            model_id=request.modelId,
            phase="supply_chain_audit",
            action="supply_chain_audited",
            outcome="success",
            details={"ip_clearance": all_cleared, "risk": risk.value},
        )

        return report

    except Exception as e:
        await log_audit_event(
            model_id=request.modelId,
            phase="supply_chain_audit",
            action="supply_chain_audited",
            outcome="failure",
            details={"error": str(e)},
        )
        raise HTTPException(status_code=500, detail=f"Supply chain audit failed: {str(e)}")


def _infer_node_type(node: dict) -> SupplyChainNodeType:
    """Infer the provenance node type from its properties."""
    if "datasetId" in node:
        return SupplyChainNodeType.dataset
    if "modelId" in node:
        return SupplyChainNodeType.model
    if "transformId" in node:
        return SupplyChainNodeType.transform
    return SupplyChainNodeType.deployment
