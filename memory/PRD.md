# PRD — AI Governance MCP Server (repo: nyayoshbharuchanb15-max/ai-compliance-mcp-server)

## Original problem statement (2026-06)
Implement a fully functional AI Governance MCP Server matching the repo docs: an on-premise
compliance orchestration service exposing a 9-phase AI audit pipeline to MCP-compatible AI
assistants, producing article-level evidence for EU AI Act, GDPR, NIST AI RMF, ISO/IEC 42001,
DPDP Act, and issuing W3C VC 2.0 certificates. Required stack: TypeScript MCP layer, FastAPI
orchestrator, Python engines, Redis event fabric, Neo4j lineage, PostgreSQL JSONB evidence,
signed credential store. Layout: /mcp-server, /orchestrator, /engines, /graph, /store,
/events, /certs, /schemas. Note: the repo actually arrived with a mature 17-tool
ComplianceStack implementation but WITHOUT the referenced docs (ARCHITECTURE.md,
AUDIT_PIPELINE.md, GOVERNANCE_AND_COMPLIANCE.md, schemas/w3c_audit_credential.jsonld) —
those were authored first as source of truth, then implemented exactly.

## User choices
User skipped clarification → defaults chosen: Redis (not NATS), Ed25519 DataIntegrityProof
(eddsa-jcs-2022), native preview run + docker-compose for on-prem, strictly MCP/API (no UI).

## Architecture (implemented 2026-06)
- /orchestrator — FastAPI (preview: served on port 8001 via /app/backend/server.py shim;
  compose: port 8010). Phase state machine, JWT client-credentials auth (HS256, PyJWT),
  scope enforcement, X-Request-Hash verification, reaudit Impact Scope Resolver,
  monitoring/observe endpoint, background Redis consumers (webhook delivery + reaudit).
- /engines — deterministic engines: risk, privacy, fairness, robustness (local corpora),
  explainability. Control versions in engines/__init__.py.
- /store — asyncpg + migrations (store/migrations/002_governance.sql): governance_runs,
  governance_phase_results (hash-chained: integrity_hash/prev_hash), governance_certificates,
  governance_events, governance_monitoring. Hashing in store/hashing.py (canonical JSON).
- /graph — Neo4j lineage per ARCHITECTURE.md §4.1 (Model, ProcessingActivity,
  RegulatoryArticle, Control, TestExecution, EvidenceArtifact, AuditRun, PhaseResult,
  RemediationTask, Certificate).
- /events — Redis Streams: governance:phase-events, governance:reaudit,
  governance:dead-letter. Idempotent (deterministic event ids + processed set), 3-attempt
  retry via pending reclaim, DLQ.
- /certs — Ed25519 signer (did:key, base58btc), VC 2.0 issuer, standalone signing service
  (certs/service.py, compose service cert-signer:8020; preview uses embedded mode,
  CERT_SIGNER_URL empty). Key at /app/.governance/ed25519.seed (gitignored).
- /mcp-server — 11 new governance tools in src/governance-tools.ts (+ governance-client.ts):
  schema validation (ajv), scope check BEFORE FastAPI, request hashing. Wired into index.ts;
  legacy 17 tools untouched. Total 28 MCP tools.
- Preview shims: /app/backend/server.py (+.env, gitignored) loads orchestrator on 8001;
  /app/frontend/package.json runs MCP server (streamable-http) on 3000.
- IMPORTANT: uvicorn --reload watches only /app/backend → after editing /app/orchestrator etc.
  run `sudo supervisorctl restart backend`.

## Phases & tools
1 intake_register, 2 map_regulatory_scope, 3 classify_risk, 4 check_data_protection,
5 evaluate_fairness, 6 test_robustness, 7 verify_explainability, 8 assemble_certification,
9 configure_monitoring; + trigger_reaudit, get_audit_run.
DAG: 1→2→3→{4,5,6,7}→8→9. Blocker ⇒ run blocked ⇒ cert prohibited (409 CERTIFICATION_BLOCKED).
Reaudit impact matrix in AUDIT_PIPELINE.md §11; updatedPhaseInputs carries trigger deltas.

## Verification status (2026-06)
- tests/governance/test_governance_pipeline.py — 10/10 PASSED (9 phases→signed VC verified,
  ordering, blocker gate, least privilege, request hash, reaudit reissue+supersede,
  reaudit revoke, drift observation → async reaudit via consumer, event ledger, DLQ).
- mcp-server: 49/49 vitest (39 legacy + 10 governance), tsc clean.
- MCP stdio smoke: 28 tools, malformed rejected at MCP layer, TS authz rejection with
  narrow-scope token, blocker surfaced, run status.
- Known pre-existing quirk (NOT introduced here): custom streamable-http transport
  terminates session on connection close (index.ts res.on("close")) — stdio is canonical.

## Local infra (preview pod)
PostgreSQL (apt, user governance/governance_secret, db evidence_store, sql/init.sql +
governance migration applied at startup), Redis (daemonized :6379), Neo4j 5 (apt,
neo4j/governance_secret, started via `neo4j start`). After pod restart: `service postgresql
start; redis-server --daemonize yes; neo4j start` then restart supervisor backend/frontend.

## Backlog / next
- DONE (2026-06): GET / on the MCP server (port 3000) serves a live status console
  (mcp-server/src/status-page.ts) — orchestrator/Postgres/Neo4j/Redis/signer health,
  9-phase table, recent evidence events, curl quickstart.
- P1: fix pre-existing streamable-http session lifecycle in mcp-server transport
- P1: GET /api/v1/runs?modelId= listing endpoint
- P2: NATS option for the event fabric; RFC 3161 timestamp anchoring for governance certs
- P2: publish deployment guide (DEPLOYMENT.md) + CI job running tests/governance against compose
