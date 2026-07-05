# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
AI Governance MCP Server — Python FastAPI Backend
══════════════════════════════════════════════════
On-premise enterprise compliance auditing engine for AI models.

This FastAPI application handles the heavy ML/audit logic for
all audit phases, including:
  - EU AI Act Risk Classification
  - Supply Chain Provenance (Neo4j)
  - Human Oversight Verification
  - Bias Assessment (Fairlearn / AIF360)
  - DPIA Generation (GDPR Art. 35)
  - Adversarial Robustness Testing
  - Weighted Audit Scoring
  - W3C VC Certificate Issuance
  - Model Drift Monitoring (Evidently AI)

ISO/IEC 42001:2023 — All audit evidence is retained in the
PostgreSQL evidence store as documented information (Clause 7.5).

Zero data egress: All operations, including cryptographic signing,
are performed in-process without external API calls.
"""

from __future__ import annotations
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from db.postgres import pg_client
from db.neo4j_client import neo4j_client
from db.user_store import user_store
from services.redis_webhook import webhook_engine
from services.auth import auth_middleware
from services.crypto_signer import crypto_signer
from middleware.pii_middleware import PIIRedactionMiddleware
from middleware.request_id import RequestIDMiddleware
from middleware.rate_limit import RateLimitMiddleware
from middleware.body_size_limit import BodySizeLimitMiddleware
from models.schemas import HealthResponse
from services.timestamping import trusted_timestamp

logger = logging.getLogger("main")

MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_SIZE", str(10 * 1024 * 1024)))


# ─── Lifespan: Startup / Shutdown ────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and teardown database connections (failures are non-fatal)."""
    # ── Startup ────────────────────────────────────────────────
    # Connect to PostgreSQL Evidence Store
    try:
        await pg_client.connect(
            user=os.environ.get("POSTGRES_USER", "governance"),
            password=os.environ.get("POSTGRES_PASSWORD", "governance_secret"),
            database=os.environ.get("POSTGRES_DB", "evidence_store"),
            host=os.environ.get("POSTGRES_HOST", "postgres"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
        )
        logger.info("PostgreSQL connected")
        # Connect User Store to PostgreSQL (auto-seeds dev users)
        if pg_client.pool:
            await user_store.connect(pg_client.pool)
    except Exception:
        logger.exception("PostgreSQL connection failed — continuing without database")

    # Connect to Neo4j Provenance Graph
    try:
        await neo4j_client.connect(
            uri=os.environ.get("NEO4J_URI", "bolt://neo4j:7687"),
            user=os.environ.get("NEO4J_USER", "neo4j"),
            password=os.environ.get("NEO4J_PASSWORD", "governance_secret"),
        )
        logger.info("Neo4j connected")
    except Exception:
        logger.exception("Neo4j connection failed — continuing without graph database")

    # Connect to Redis Webhook Engine
    try:
        await webhook_engine.connect(
            url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
        )
        logger.info("Redis connected")
    except Exception:
        logger.exception("Redis connection failed — continuing without Redis")

    yield

    # ── Shutdown ────────────────────────────────────────────────
    # Flush any pending timestamp anchors
    try:
        trusted_timestamp.flush_batch()
    except Exception:
        logger.warning("Failed to flush timestamp batch on shutdown")

    await pg_client.close()
    await neo4j_client.close()
    await webhook_engine.close()


# ─── FastAPI Application ─────────────────────────────────────────

app = FastAPI(
    title="AI Governance MCP Server — Backend",
    description="On-premise AI compliance auditing engine for EU AI Act, "
                "NIST AI RMF, ISO/IEC 42001, GDPR, and India DPDP Act 2023.",
    version="2.0.0",
    lifespan=lifespan,
)

# ── Middleware Stack ─────────────────────────────────────────────
# Order matters: RequestID → BodySize → RateLimit → CORS → TrustedHost → Auth → PII

app.add_middleware(RequestIDMiddleware)

app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080,http://localhost:3001").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.environ.get(
        "TRUSTED_HOSTS", "localhost,python-backend,mcp-server,127.0.0.1"
    ).split(","),
)

# Auth middleware (applied to all /api/* routes except /api/auth/* and /health)
app.middleware("http")(auth_middleware)

# PII Redaction middleware (applied to all /api/* routes except /health and /api/auth/*)
app.add_middleware(PIIRedactionMiddleware)

# Rate limit middleware (applied to all /api/* routes; degrades when Redis is down)
app.add_middleware(RateLimitMiddleware)


# ─── Health Check ────────────────────────────────────────────────

async def _probe_postgres() -> str:
    if pg_client.pool is None:
        return "disconnected"
    try:
        async with pg_client.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return "connected"
    except Exception:
        return "unreachable"


async def _probe_neo4j() -> str:
    if neo4j_client.driver is None:
        return "disconnected"
    try:
        result = await neo4j_client.run_query("RETURN 1 AS ok")
        return "connected" if result else "unreachable"
    except Exception:
        return "unreachable"


async def _probe_redis() -> str:
    if webhook_engine.client is None:
        return "disconnected"
    try:
        await webhook_engine.client.ping()
        return "connected"
    except Exception:
        return "unreachable"


async def _probe_crypto() -> str:
    try:
        sig = crypto_signer.sign_payload(b"health")
        ok = crypto_signer.verify_signature(b"health", sig)
        return "operational" if ok else "malfunction"
    except Exception:
        return "unavailable"


async def _probe_timestamping() -> str:
    try:
        pending = trusted_timestamp.pending_batch_size
        anchored = len(trusted_timestamp.get_anchored_roots())
        return f"operational (pending={pending}, anchored={anchored})"
    except Exception:
        return "unavailable"


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with deep probes of all dependencies."""
    postgres_status = await _probe_postgres()
    neo4j_status = await _probe_neo4j()
    redis_status = await _probe_redis()
    crypto_status = await _probe_crypto()
    timestamping_status = await _probe_timestamping()

    overall = "ok"
    if any(s in ("unreachable", "malfunction", "unavailable") for s in (
        postgres_status, neo4j_status, redis_status, crypto_status, timestamping_status
    )):
        overall = "degraded"
    if all(s == "disconnected" for s in (postgres_status, neo4j_status, redis_status)):
        overall = "unavailable"

    request_id = ""
    return HealthResponse(
        status=overall,
        services={
            "postgres": postgres_status,
            "neo4j": neo4j_status,
            "redis": redis_status,
            "crypto": crypto_status,
            "timestamping": timestamping_status,
        },
    )


# ─── Register Routers ────────────────────────────────────────────

from routers.auth import router as auth_router
from routers.risk import router as risk_router
from routers.supply_chain import router as supply_chain_router
from routers.human_oversight import router as human_oversight_router
from routers.bias import router as bias_router
from routers.dpia import router as dpia_router
from routers.adversarial import router as adversarial_router
from routers.scoring import router as scoring_router
from routers.certificate import router as certificate_router
from routers.drift import router as drift_router
from routers.dpdp import router as dpdp_router
from routers.ropa import router as ropa_router
from routers.dsar import router as dsar_router
from routers.session_memory import router as session_memory_router
from routers.rag_quality import router as rag_quality_router
from routers.prompt_audit import router as prompt_audit_router
from routers.agent_trust import router as agent_trust_router
from routers.tool_permissions import router as tool_permissions_router
from routers.agent_autonomy import router as agent_autonomy_router
from routers.crl import router as crl_router

app.include_router(auth_router)
app.include_router(risk_router)
app.include_router(supply_chain_router)
app.include_router(human_oversight_router)
app.include_router(bias_router)
app.include_router(dpia_router)
app.include_router(adversarial_router)
app.include_router(scoring_router)
app.include_router(certificate_router)
app.include_router(drift_router)
app.include_router(dpdp_router)
app.include_router(ropa_router)
app.include_router(dsar_router)
app.include_router(session_memory_router)
app.include_router(rag_quality_router)
app.include_router(prompt_audit_router)
app.include_router(agent_trust_router)
app.include_router(tool_permissions_router)
app.include_router(agent_autonomy_router)
app.include_router(crl_router)
