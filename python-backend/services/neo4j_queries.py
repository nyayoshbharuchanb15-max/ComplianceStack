# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Neo4j Provenance Queries — Supply Chain Traceability
─────────────────────────────────────────────────────
Executable Cypher queries for AI model supply chain provenance.

ISO/IEC 42001:2023 Clause 7.4.3 — Supply Chain Traceability:
  - Full lineage tracking for Model, Dataset, Transform, Component nodes
  - IP clearance audit across all connected components
  - License compatibility validation for supply chain compliance

EU AI Act Art. 10 — Data Governance:
  - Traceability of training data origins
  - Documentation of data processing pipelines

NIST AI RMF GOVERN 1.2 — Supply Chain Transparency:
  - Component-level provenance tracking
  - Audit evidence for regulatory compliance
"""

from __future__ import annotations
from typing import Any, Optional
from neo4j import Driver, Session


def upsert_model(
    driver: Driver,
    model_id: str,
    name: str,
    version: str,
    description: str = "",
) -> dict[str, Any]:
    """
    Create or update a Model node.

    Uses MERGE to ensure idempotent upserts — safe for repeated calls.
    """
    try:
        query = """
        MERGE (m:Model {modelId: $model_id})
        SET m.name = $name,
            m.version = $version,
            m.description = $description,
            m.updatedAt = timestamp()
        RETURN m.modelId AS modelId, m.name AS name,
               m.version AS version, m.description AS description
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id, name=name,
                                 version=version, description=description)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {"success": False, "error": "No record returned from upsert"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def upsert_dataset(
    driver: Driver,
    dataset_id: str,
    name: str,
    license: str = "UNKNOWN",
    source: str = "",
) -> dict[str, Any]:
    """
    Create or update a Dataset node.

    Tracks dataset metadata including licensing for IP compliance.
    """
    try:
        query = """
        MERGE (d:Dataset {datasetId: $dataset_id})
        SET d.name = $name,
            d.license = $license,
            d.source = $source,
            d.updatedAt = timestamp()
        RETURN d.datasetId AS datasetId, d.name AS name,
               d.license AS license, d.source AS source
        """
        with driver.session() as session:
            result = session.run(query, dataset_id=dataset_id, name=name,
                                 license=license, source=source)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {"success": False, "error": "No record returned from upsert"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def upsert_transform(
    driver: Driver,
    transform_id: str,
    name: str,
    description: str = "",
) -> dict[str, Any]:
    """
    Create or update a Transform node.
    """
    try:
        query = """
        MERGE (t:Transform {transformId: $transform_id})
        SET t.name = $name,
            t.description = $description,
            t.updatedAt = timestamp()
        RETURN t.transformId AS transformId, t.name AS name,
               t.description AS description
        """
        with driver.session() as session:
            result = session.run(query, transform_id=transform_id, name=name,
                                 description=description)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {"success": False, "error": "No record returned from upsert"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def upsert_component(
    driver: Driver,
    component_id: str,
    name: str,
    license: str = "UNKNOWN",
    origin: str = "",
    ip_cleared: bool = False,
) -> dict[str, Any]:
    """
    Create or update a Component node with IP clearance status.
    """
    try:
        query = """
        MERGE (c:Component {componentId: $component_id})
        SET c.name = $name,
            c.license = $license,
            c.origin = $origin,
            c.ipCleared = $ip_cleared,
            c.updatedAt = timestamp()
        RETURN c.componentId AS componentId, c.name AS name,
               c.license AS license, c.origin AS origin,
               c.ipCleared AS ipCleared
        """
        with driver.session() as session:
            result = session.run(query, component_id=component_id, name=name,
                                 license=license, origin=origin,
                                 ip_cleared=ip_cleared)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {"success": False, "error": "No record returned from upsert"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def link_trained_on(
    driver: Driver,
    model_id: str,
    dataset_id: str,
) -> dict[str, Any]:
    """
    Create TRAINED_ON relationship between Model and Dataset.

    Uses MERGE to prevent duplicate relationships.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        MATCH (d:Dataset {datasetId: $dataset_id})
        MERGE (m)-[r:TRAINED_ON]->(d)
        SET r.createdAt = timestamp()
        RETURN m.modelId AS modelId, d.datasetId AS datasetId,
               type(r) AS relationship
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id,
                                 dataset_id=dataset_id)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {
                "success": False,
                "error": "Model or Dataset node not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def link_fine_tuned_on(
    driver: Driver,
    model_id: str,
    dataset_id: str,
) -> dict[str, Any]:
    """
    Create FINE_TUNED_ON relationship between Model and Dataset.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        MATCH (d:Dataset {datasetId: $dataset_id})
        MERGE (m)-[r:FINE_TUNED_ON]->(d)
        SET r.createdAt = timestamp()
        RETURN m.modelId AS modelId, d.datasetId AS datasetId,
               type(r) AS relationship
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id,
                                 dataset_id=dataset_id)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {
                "success": False,
                "error": "Model or Dataset node not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def link_deployed_on(
    driver: Driver,
    model_id: str,
    deployment_id: str,
) -> dict[str, Any]:
    """
    Create DEPLOYED_ON relationship between Model and Deployment.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        MATCH (d:Deployment {deploymentId: $deployment_id})
        MERGE (m)-[r:DEPLOYED_ON]->(d)
        SET r.createdAt = timestamp()
        RETURN m.modelId AS modelId, d.deploymentId AS deploymentId,
               type(r) AS relationship
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id,
                                 deployment_id=deployment_id)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {
                "success": False,
                "error": "Model or Deployment node not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def link_contains(
    driver: Driver,
    parent_id: str,
    child_id: str,
    parent_type: str = "Model",
    child_type: str = "Component",
) -> dict[str, Any]:
    """
    Create CONTAINS relationship between parent and child nodes.
    """
    try:
        query = f"""
        MATCH (p:{parent_type} {{modelId: $parent_id}})
        MATCH (c:{child_type} {{componentId: $child_id}})
        MERGE (p)-[r:CONTAINS]->(c)
        SET r.createdAt = timestamp()
        RETURN p.modelId AS parentId, c.componentId AS childId,
               type(r) AS relationship
        """
        with driver.session() as session:
            result = session.run(query, parent_id=parent_id,
                                 child_id=child_id)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {
                "success": False,
                "error": f"Parent ({parent_type}) or Child ({child_type}) node not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def link_derived_from(
    driver: Driver,
    source_id: str,
    derived_id: str,
    source_type: str = "Model",
    derived_type: str = "Model",
) -> dict[str, Any]:
    """
    Create DERIVED_FROM relationship between two nodes.
    """
    try:
        query = f"""
        MATCH (s:{source_type} {{modelId: $source_id}})
        MATCH (d:{derived_type} {{modelId: $derived_id}})
        MERGE (d)-[r:DERIVED_FROM]->(s)
        SET r.createdAt = timestamp()
        RETURN s.modelId AS sourceId, d.modelId AS derivedId,
               type(r) AS relationship
        """
        with driver.session() as session:
            result = session.run(query, source_id=source_id,
                                 derived_id=derived_id)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record),
                }
            return {
                "success": False,
                "error": f"Source ({source_type}) or Derived ({derived_type}) node not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_full_provenance(
    driver: Driver,
    model_id: str,
    max_hops: int = 3,
) -> dict[str, Any]:
    """
    Get full provenance trace for a model.

    Traverses all connected nodes up to max_hops levels, returning
    the complete supply chain lineage including:
    - Training datasets
    - Fine-tuning datasets
    - Components (code, libraries, pre-trained models)
    - Transformations applied
    - Deployment targets

    ISO/IEC 42001:2023 Clause 7.4.3 — full lineage traceability.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        OPTIONAL MATCH path = (m)-[*1..$max_hops]-(connected)
        WITH m, collect({
            nodes: [n IN nodes(path) | {
                labels: labels(n),
                properties: properties(n)
            }],
            relationships: [r IN relationships(path) | {
                type: type(r),
                properties: properties(r)
            }]
        }) AS paths
        RETURN {
            model: properties(m),
            lineage: [p IN paths WHERE p IS NOT NULL],
            nodeCount: size([n IN nodes(path) | n]),
            relationshipCount: size([r IN relationships(path) | r])
        } AS provenance
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id, max_hops=max_hops)
            record = result.single()
            if record and record["provenance"]:
                provenance = dict(record["provenance"])
                provenance["nodeCount"] = len(provenance.get("lineage", []))
                return {
                    "success": True,
                    "data": provenance,
                }
            return {
                "success": False,
                "error": f"Model {model_id} not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def audit_ip_clearance(
    driver: Driver,
    model_id: str,
) -> dict[str, Any]:
    """
    Find all uncleared IP components for a model.

    Traverses the supply chain to identify components that have not
    been cleared for intellectual property compliance. Returns details
    of each uncleared component including name, license, and origin.

    EU AI Act Art. 10 — IP compliance in training data and components.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        OPTIONAL MATCH (m)-[*1..3]-(component:Component)
        WHERE component.ipCleared = false OR component.ipCleared IS NULL
        RETURN collect({
            componentId: component.componentId,
            name: component.name,
            license: component.license,
            origin: component.origin,
            ipCleared: component.ipCleared
        }) AS unclearedComponents,
        count(component) AS totalUncleared
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": {
                        "modelId": model_id,
                        "unclearedComponents": record["unclearedComponents"],
                        "totalUncleared": record["totalUncleared"],
                        "isCompliant": record["totalUncleared"] == 0,
                    },
                }
            return {
                "success": False,
                "error": f"Model {model_id} not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_license_compatibility(
    driver: Driver,
    model_id: str,
) -> dict[str, Any]:
    """
    Check license compatibility across all components in the supply chain.

    Classifies each component's license as:
    - COMPATIBLE: Permissive licenses (MIT, Apache-2.0, BSD-2, BSD-3)
    - RESTRICTIVE: Copyleft licenses (GPL, AGPL, LGPL) requiring review
    - UNKNOWN: Unrecognized or missing license
    - CONFLICT: Mix of incompatible licenses detected

    NIST AI RMF GOVERN 1.2 — supply chain license transparency.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        OPTIONAL MATCH (m)-[*1..3]-(component:Component)
        RETURN collect({
            componentId: component.componentId,
            name: component.name,
            license: component.license,
            ipCleared: component.ipCleared,
            licenseStatus: CASE
                WHEN component.license IN [
                    'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause',
                    'ISC', '0BSD', 'Unlicense', 'CC0-1.0', 'CC-BY-4.0'
                ] THEN 'COMPATIBLE'
                WHEN component.license IN [
                    'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1',
                    'LGPL-3.0', 'MPL-2.0', 'CDDL-1.1'
                ] THEN 'RESTRICTIVE'
                WHEN component.license IS NULL OR component.license = ''
                    THEN 'UNKNOWN'
                ELSE 'REVIEW_REQUIRED'
            END
        }) AS components,
        count(component) AS totalComponents
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id)
            record = result.single()
            if record:
                components = record["components"]
                compatible = [c for c in components
                              if c["licenseStatus"] == "COMPATIBLE"]
                restrictive = [c for c in components
                               if c["licenseStatus"] == "RESTRICTIVE"]
                unknown = [c for c in components
                           if c["licenseStatus"] == "UNKNOWN"]
                review = [c for c in components
                          if c["licenseStatus"] == "REVIEW_REQUIRED"]

                has_conflict = len(restrictive) > 0 and len(compatible) > 0

                return {
                    "success": True,
                    "data": {
                        "modelId": model_id,
                        "components": components,
                        "summary": {
                            "totalComponents": record["totalComponents"],
                            "compatible": len(compatible),
                            "restrictive": len(restrictive),
                            "unknown": len(unknown),
                            "reviewRequired": len(review),
                        },
                        "licenseStatus": (
                            "CONFLICT" if has_conflict
                            else "COMPATIBLE" if len(restrictive) == 0
                            and len(unknown) == 0
                            else "REVIEW_REQUIRED"
                        ),
                        "restrictiveComponents": restrictive,
                        "unknownLicenseComponents": unknown,
                    },
                }
            return {
                "success": False,
                "error": f"Model {model_id} not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_component_dependencies(
    driver: Driver,
    model_id: str,
) -> dict[str, Any]:
    """
    Get all component dependencies for a model.

    Returns a dependency tree showing all connected components with
    their relationship types, forming the supply chain graph.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        OPTIONAL MATCH path = (m)-[*1..3]-(connected)
        WITH m, collect({
            path: [n IN nodes(path) | {
                id: CASE
                    WHEN 'Model' IN labels(n) THEN n.modelId
                    WHEN 'Dataset' IN labels(n) THEN n.datasetId
                    WHEN 'Transform' IN labels(n) THEN n.transformId
                    WHEN 'Component' IN labels(n) THEN n.componentId
                    WHEN 'Deployment' IN labels(n) THEN n.deploymentId
                    ELSE NULL
                END,
                label: head(labels(n)),
                name: COALESCE(n.name, n.modelId, 'unknown'),
                properties: properties(n)
            }],
            relationships: [r IN relationships(path) | type(r)]
        }) AS paths
        RETURN {
            modelId: m.modelId,
            modelName: m.name,
            dependencies: [p IN paths | {
                nodes: [item IN p.path | item],
                relationshipChain: p.relationships,
                depth: size(p.relationships)
            }]
        } AS dependencyGraph
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id)
            record = result.single()
            if record and record["dependencyGraph"]:
                dep_graph = dict(record["dependencyGraph"])
                unique_components = set()
                for dep in dep_graph.get("dependencies", []):
                    for node in dep.get("nodes", []):
                        if node.get("id"):
                            unique_components.add(node["id"])

                dep_graph["uniqueComponentCount"] = len(unique_components)
                return {
                    "success": True,
                    "data": dep_graph,
                }
            return {
                "success": False,
                "error": f"Model {model_id} not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def record_audit_evidence(
    driver: Driver,
    model_id: str,
    audit_phase: str,
    evidence_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Store audit evidence in Neo4j as a timestamped property on the Model.

    Appends evidence to the model's auditEvidence list, maintaining
    an immutable audit trail within the graph database.

    ISO/IEC 42001:2023 Clause 7.5 — Documented Information:
    - Evidence is retained with timestamps
    - Audit phases are versioned and traceable
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        SET m.auditEvidence = COALESCE(m.auditEvidence, []) + [{
            auditPhase: $audit_phase,
            evidence: $evidence_data,
            recordedAt: timestamp(),
            evidenceId: randomUUID()
        }]
        RETURN m.modelId AS modelId,
               size(m.auditEvidence) AS totalEvidenceEntries
        """
        with driver.session() as session:
            result = session.run(
                query,
                model_id=model_id,
                audit_phase=audit_phase,
                evidence_data=evidence_data,
            )
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": {
                        "modelId": record["modelId"],
                        "totalEvidenceEntries": record["totalEvidenceEntries"],
                        "auditPhase": audit_phase,
                    },
                }
            return {
                "success": False,
                "error": f"Model {model_id} not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_audit_evidence(
    driver: Driver,
    model_id: str,
    audit_phase: Optional[str] = None,
) -> dict[str, Any]:
    """
    Retrieve audit evidence for a model, optionally filtered by phase.
    """
    try:
        if audit_phase:
            query = """
            MATCH (m:Model {modelId: $model_id})
            UNWIND m.auditEvidence AS evidence
            WHERE evidence.auditPhase = $audit_phase
            RETURN collect(evidence) AS evidenceList
            """
            params = {"model_id": model_id, "audit_phase": audit_phase}
        else:
            query = """
            MATCH (m:Model {modelId: $model_id})
            RETURN COALESCE(m.auditEvidence, []) AS evidenceList
            """
            params = {"model_id": model_id}

        with driver.session() as session:
            result = session.run(query, **params)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": {
                        "modelId": model_id,
                        "evidenceList": record["evidenceList"],
                        "totalEntries": len(record["evidenceList"]),
                    },
                }
            return {
                "success": False,
                "error": f"Model {model_id} not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_model_by_id(
    driver: Driver,
    model_id: str,
) -> dict[str, Any]:
    """
    Retrieve a Model node by its ID.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        RETURN properties(m) AS model
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id)
            record = result.single()
            if record:
                return {
                    "success": True,
                    "data": dict(record["model"]),
                }
            return {
                "success": False,
                "error": f"Model {model_id} not found",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def delete_model_provenance(
    driver: Driver,
    model_id: str,
) -> dict[str, Any]:
    """
    Delete a Model node and all its relationships.

    WARNING: This is a destructive operation. Use with caution.
    """
    try:
        query = """
        MATCH (m:Model {modelId: $model_id})
        DETACH DELETE m
        RETURN count(m) AS deletedCount
        """
        with driver.session() as session:
            result = session.run(query, model_id=model_id)
            record = result.single()
            deleted = record["deletedCount"] if record else 0
            return {
                "success": True,
                "data": {
                    "modelId": model_id,
                    "deletedCount": deleted,
                },
            }
    except Exception as e:
        return {"success": False, "error": str(e)}
