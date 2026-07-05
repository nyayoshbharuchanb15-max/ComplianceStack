# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Neo4j Provenance Graph Client
───────────────────────────────
Maintains the interconnected supply chain relationships for AI model
provenance tracing.

The graph supports queries like:
  - "What datasets were used to train this model?"
  - "Which third-party components have unresolved IP issues?"
  - "What is the full transitive dependency chain?"

ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain traceability requires
maintaining provenance records for all AI system components.
"""

from __future__ import annotations
import logging
import os
from typing import Any, Optional
from neo4j import AsyncGraphDatabase, AsyncDriver

logger = logging.getLogger("neo4j_client")


class Neo4jClient:
    """Async Neo4j client for the provenance graph."""

    def __init__(self):
        self.driver: Optional[AsyncDriver] = None

    async def connect(
        self,
        uri: str = "bolt://neo4j:7687",
        user: str = "neo4j",
        password: str = "governance_secret",
    ) -> None:
        """Initialize Neo4j driver with async connection."""
        self.driver = AsyncGraphDatabase.driver(uri, auth=(user, password))

    async def close(self) -> None:
        """Close the driver."""
        if self.driver:
            await self.driver.close()

    async def run_query(self, query: str, params: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """Execute a Cypher query and return results."""
        if not self.driver:
            logger.warning("Neo4j driver not available — returning empty result")
            return []

        try:
            async with self.driver.session() as session:
                result = await session.run(query, params or {})
                records = await result.data()
                return records
        except Exception:
            logger.exception("Neo4j query failed — returning empty result")
            return []

    async def add_model_node(self, model_id: str, metadata: dict[str, Any]) -> None:
        """Create or update a model node in the provenance graph."""
        await self.run_query(
            """
            MERGE (m:Model {modelId: $model_id})
            SET m += $metadata,
                m.updatedAt = timestamp()
            """,
            {"model_id": model_id, "metadata": metadata},
        )

    async def add_dataset_node(
        self, dataset_id: str, metadata: dict[str, Any]
    ) -> None:
        """Create a dataset node."""
        await self.run_query(
            """
            MERGE (d:Dataset {datasetId: $dataset_id})
            SET d += $metadata,
                d.updatedAt = timestamp()
            """,
            {"dataset_id": dataset_id, "metadata": metadata},
        )

    async def add_training_relationship(
        self, model_id: str, dataset_id: str, metadata: dict[str, Any]
    ) -> None:
        """Link a model to its training dataset."""
        await self.run_query(
            """
            MATCH (m:Model {modelId: $model_id})
            MATCH (d:Dataset {datasetId: $dataset_id})
            MERGE (m)-[r:TRAINED_ON]->(d)
            SET r += $metadata,
                r.updatedAt = timestamp()
            """,
            {
                "model_id": model_id,
                "dataset_id": dataset_id,
                "metadata": metadata,
            },
        )

    async def get_provenance_graph(
        self, model_id: str, deep: bool = False
    ) -> list[dict[str, Any]]:
        """
        Retrieve the full provenance graph for a model.

        When deep=True, traverses all transitive dependencies.
        """
        if deep:
            query = """
                MATCH (m:Model {modelId: $model_id})
                OPTIONAL MATCH path = (m)-[*1..3]-(connected)
                UNWIND nodes(path) AS node
                RETURN DISTINCT node
                """
        else:
            query = """
                MATCH (m:Model {modelId: $model_id})
                OPTIONAL MATCH (m)-[r]-(connected)
                RETURN DISTINCT m AS model, collect(DISTINCT connected) AS connections
                """

        return await self.run_query(query, {"model_id": model_id})

    async def check_ip_clearance(self, model_id: str) -> dict[str, Any]:
        """Verify IP clearance for all supply chain components."""
        result = await self.run_query(
            """
            MATCH (m:Model {modelId: $model_id})
            OPTIONAL MATCH (m)-[*1..3]-(component)
            WHERE component.ipCleared IS NOT NULL
            RETURN
                count(component) AS totalComponents,
                sum(CASE WHEN component.ipCleared = true THEN 1 ELSE 0 END) AS clearedComponents,
                collect(DISTINCT component.name) AS componentNames
            """,
            {"model_id": model_id},
        )
        if not result:
            return {"totalComponents": 0, "clearedComponents": 0, "allCleared": False}

        row = result[0]
        total = row.get("totalComponents", 0) or 0
        cleared = row.get("clearedComponents", 0) or 0
        return {
            "totalComponents": total,
            "clearedComponents": cleared,
            "allCleared": total == cleared,
        }


# Singleton instance
neo4j_client = Neo4jClient()
