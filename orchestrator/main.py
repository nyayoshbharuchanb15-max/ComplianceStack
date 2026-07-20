# SPDX-License-Identifier: Apache-2.0
"""AI Governance Orchestrator — FastAPI application entrypoint."""
from __future__ import annotations
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from certs.signer import get_signer
from events.fabric import PHASE_EVENTS_STREAM, REAUDIT_STREAM, fabric
from graph.client import graph
from orchestrator.config import validate_startup_config
from store import evidence as store_evidence
from store.db import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("orchestrator.main")

# Fail-fast validation: refuse to import (and therefore to boot) with weak or
# missing service-account / JWT secrets. Raises InsecureConfigError.
validate_startup_config()


async def _deliver_phase_event(envelope: dict) -> None:
    """Internal webhook fan-out: persist delivery to the governance_events ledger."""
    if envelope.get("type") == "governance.test.poison":
        raise RuntimeError("poison event — cannot be delivered")
    payload = envelope.get("payload", {})
    await store_evidence.record_event(
        envelope["eventId"], PHASE_EVENTS_STREAM, envelope.get("type", "unknown"),
        payload, status="delivered", attempts=envelope.get("attempt", 1),
        run_id=payload.get("runId"), phase_key=payload.get("phase"))


async def _handle_reaudit_trigger(envelope: dict) -> None:
    from orchestrator.reaudit import execute_reaudit
    payload = envelope.get("payload", {})
    result = await execute_reaudit(payload["modelId"], payload["trigger"],
                                   actor="monitoring-fabric")
    await store_evidence.record_event(
        envelope["eventId"], REAUDIT_STREAM, "reaudit.executed",
        {"modelId": payload["modelId"], "trigger": payload["trigger"],
         "reauditRunId": result["reauditRunId"],
         "certificateAction": result["certificateAction"].get("action")},
        status="delivered", attempts=envelope.get("attempt", 1),
        run_id=result["reauditRunId"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    await db.migrate()
    logger.info("PostgreSQL evidence store ready")

    try:
        await graph.connect()
        await graph.migrate()
        logger.info("Neo4j control graph ready")
    except Exception:
        logger.exception("Neo4j unavailable — lineage degraded")

    try:
        await fabric.connect()
        consumer = os.environ.get("HOSTNAME", "orchestrator-1")
        fabric.start_consumer(PHASE_EVENTS_STREAM, "webhook-delivery", consumer,
                              _deliver_phase_event)
        fabric.start_consumer(REAUDIT_STREAM, "reaudit-workers", consumer,
                              _handle_reaudit_trigger)
        logger.info("Redis event fabric ready (consumers started)")
    except Exception:
        logger.exception("Redis unavailable — event fabric degraded")

    signer = get_signer()
    logger.info("Certificate signer ready (did=%s)", signer.did)

    yield

    await fabric.close()
    await graph.close()
    await db.close()


app = FastAPI(
    title="AI Governance Orchestrator",
    description="9-phase AI audit pipeline with deterministic gating and VC 2.0 certification "
                "(see ARCHITECTURE.md / AUDIT_PIPELINE.md).",
    version="1.0.0",
    lifespan=lifespan,
)

from orchestrator.routes import router  # noqa: E402

app.include_router(router)


async def _health_payload() -> dict:
    postgres = "connected" if db.pool else "disconnected"
    neo4j_status = "connected" if graph.available else "disconnected"
    redis_status = "disconnected"
    if fabric.available:
        try:
            await fabric.client.ping()
            redis_status = "connected"
        except Exception:
            redis_status = "unreachable"
    signer_status = "operational"
    try:
        get_signer()
    except Exception:
        signer_status = "unavailable"
    statuses = (postgres, neo4j_status, redis_status, signer_status)
    overall = "ok" if all(s in ("connected", "operational") for s in statuses) else "degraded"
    return {"status": overall, "services": {"postgres": postgres, "neo4j": neo4j_status,
                                            "redis": redis_status, "certSigner": signer_status}}


@app.get("/health")
async def health():
    return await _health_payload()


@app.get("/api/v1/health")
async def health_api():
    return await _health_payload()
