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

## 2026-02 iteration (part 4) — security-fix test refactor + Emergent Google Sign-In
User asked for two things: (1) verify the security patches from part 3 (hardcoded
default secrets removed, VC pubkey pinned, atomic cert revocation) actually stick
by rebuilding the test suite around env-sourced secrets; and (2) add
"Sign in with Google" so a human auditor can log in without needing a client-
credentials secret from the vault. Per user product decision, Google-authenticated
users are minted a **governance-admin** JWT (full scopes).

**Test suite refactor**
- `/app/tests/governance/conftest.py` — reads `/app/backend/.env` once and
  exports a `CREDS` dict pulled from `GOV_ADMIN_SECRET` / `GOV_INTAKE_SECRET`
  / `GOV_AUDIT_SECRET` / `GOV_CERT_SECRET`. Raises RuntimeError at collection
  if any env var is unset.
- All 4 pre-existing test modules (`test_new_backend_endpoints.py`,
  `test_artifacts_and_citations.py`, `test_gap_analysis.py`,
  `test_governance_pipeline.py`) refactored to import `CREDS` from
  `conftest` — zero hardcoded secrets remain in `/app/tests`.
- `/app/mcp-server/src/governance-client.ts` — removed the
  `|| "govern-admin-secret-dev"` fallback; unset env var now yields empty
  string so the client fails fast against the orchestrator (which returns
  401 INVALID_CLIENT). `dist/` rebuilt.

**Emergent-managed Google Sign-In**
- `/app/orchestrator/google_auth.py` — one module implementing the full
  playbook: fetches Emergent's `/session-data` endpoint, persists the
  session in Postgres, mints an HS256 governance JWT bound to role
  `governance-admin`, and sets an HttpOnly + Secure + SameSite=None
  `governance_session` cookie. Testing-only escape hatch guarded by
  `GOV_ALLOW_TEST_AUTH=1` + matching `GOOGLE_AUTH_TEST_SESSION_ID`
  allows deterministic backend tests without depending on
  `demobackend.emergentagent.com`.
- `/app/orchestrator/routes.py` — three new endpoints under `/api/v1`:
  `POST /auth/google/session`, `GET /auth/me`, `POST /auth/logout`.
- `/app/orchestrator/main.py` — CORS middleware with `allow_credentials=True`
  and regex `.*` (echoes request origin per starlette's rules; env var
  `CORS_ORIGINS` overrides).
- `/app/store/migrations/005_google_auth.sql` — `governance_google_sessions`
  table (session_token PK, user_id/email/name/picture/role, TTL 7 days).
- `/app/mcp-server/ui/workbench.js` — top-level `load` handler now detects
  `#session_id=` in the URL fragment BEFORE the router runs, exchanges it
  against `/api/v1/auth/google/session`, scrubs the hash, and lands on
  `#/dashboard`. Login page has a prominent "Sign in with Google" button
  (`data-testid="login-google-btn"`) above the service-account cards.
  Sign-out now fires `POST /api/v1/auth/logout` before clearing
  sessionStorage. `fetch` calls include `credentials: "include"` so the
  session cookie flows.
- `/app/mcp-server/ui/workbench.css` — `.google-btn` styled with the
  four-quadrant conic gradient Google icon and `.or-divider` between
  Google + service accounts.
- `/app/tests/governance/test_google_auth.py` — 8 new pytest cases
  covering all endpoints + JWT usability + logout.

**Data-plane recovery**
- Pod restart wiped Postgres/Neo4j/Redis binaries. Reinstalled Postgres 15,
  Neo4j 5, Redis via apt; supervisor conf
  (`/etc/supervisor/conf.d/governance_data_plane.conf`) picks them up
  and keeps them alive.

**Verification (iteration 5)**: testing agent — 100% backend / 100%
frontend. 36/36 python E2E (28 existing + 8 new Google Auth) + 52/52
vitest all pass. Only lingering items are the 3 pre-existing low-priority
console TypeErrors from stale render callbacks (carried over from
iteration 4, non-blocking).

## 2026-02 iteration (part 3) — data-testid coverage + artifact detail modal + env recovery
- **data-testid attributes** on every interactive element via a `tid()` helper
  in `mcp-server/ui/workbench.js` — login roles, sidebar nav, dashboard KPIs,
  wizard steps + run-demo/back/next/per-phase-run buttons, artifact editor
  (name/type/uri/file/add/remove), run detail page + KPIs + timeline heads
  + timeline gap/citation rows, artifact table rows, cert detail + revoke,
  verify page + checks + VC JSON, events page + tables + inject-DLQ button,
  reaudit form, modal + close button, toast container. Every page also has
  a page-level test id (`login-page`, `dashboard-page`, `audit-wizard-page`,
  `run-detail-page`, etc.). Interactive rows carry `data-run-id` /
  `data-cert-id` / `data-artifact-id` attributes for stable lookup.
- **Artifact detail modal** — new `openModal()` and `openArtifactDetail()` in
  `workbench.js`. Clicking any row in the Evidence Artifacts table on the
  run detail page (or any gap/citation row inside an expanded phase) opens a
  modal that fetches `GET /api/v1/artifacts/{artifactId}` and shows: name +
  artifactId + type + mimeType, extraction-status pill, gap-score %, blocker
  and warning gap counts, list of cited phases (tags), full per-section gap
  findings with regulatory framework + article + section + first-matching
  excerpt from the document + verdict pill, and the full extracted document
  text (up to ~300 KB, wrapped preformatted). Escape closes the modal;
  click-outside closes.
- **CSS** — `.cit-row.clickable` hover style (subtle border+background
  emerald tint) added so users see the rows are clickable.
- **Stale-render null-guards** — three async `document.getElementById(...)`
  callers on dashboard/runs/certs/events pages were guarded so that
  navigating away before the fetch resolves no longer throws
  `TypeError: Cannot read properties of null` in the console.
- **Data-plane recovery** — Postgres/Neo4j/Redis were reinstalled after a
  pod restart and adopted under supervisor as `governance-postgres`,
  `governance-neo4j`, `governance-redis` via
  `/etc/supervisor/conf.d/governance_data_plane.conf`. Data plane now
  survives pod restarts. `neo4j` data dir chown'd to the `neo4j` user.

**Verification (iteration 4)**: testing agent — 100 % backend / 100 %
frontend. 28/28 python E2E + 52/52 vitest. Zero critical or minor issues;
the three low-priority console `TypeError` reports have now been fixed
with null-guards on the async render callbacks.

## 2026-02 iteration (part 2) — P1 bug fix + rich artifact ingest + document gap analysis
The user marked P1 (MCP streamable-http session-close lifecycle) as a real bug and
explicitly asked for the diagnostic core: "article-level, document-level diagnosis
of what's missing or non-compliant, not just presence/absence checks."

**P1 bug fix (streamable-http session lifecycle)**
- `mcp-server/src/index.ts` — removed the premature `res.on('close', () =>
  sessionManager.terminateSession(session.id))` on the initial POST /mcp
  response. Sessions now persist across the initial POST close and are only
  terminated by explicit DELETE /mcp or by the idle-cleanup timer in
  `sessionManager.startCleanup()`. Also scoped `validateOrigin` to /mcp routes
  only (was previously global — this was blocking the SPA in the previous
  iteration).
- `mcp-server/src/streamable-http-transport.ts` — added `detachSSE(res)` so
  the transport clears its `_sseRes` pointer when the SSE stream closes and
  subsequent `send()` calls queue messages for reconnection instead of
  silently writing to a dead response.
- `mcp-server/src/__tests__/session-lifecycle.test.ts` — 3 vitest regression
  tests (session survives initial POST close, DELETE terminates, detachSSE
  queues on reconnect).

**Rich artifact ingest + gap analysis**
- `store/migrations/004_gap_analysis.sql` — new extracted_text /
  extraction_status / gap_findings / gap_score columns on governance_artifacts,
  plus a governance_phase_gaps table.
- `engines/document_extractor.py` — offline text extraction for PDF
  (pypdf 6+), CSV, JSON, Markdown, plain text; server-side sha256 over the
  actual bytes.
- `engines/gap_analysis.py` — SPECIFICATIONS matrix declaring, for every
  document-typed artifact, the required sections mapped to sub-articles
  (GDPR Art. 35(7)(a) "Systematic description", Art. 35(7)(d) "Measures
  envisaged", EU-AI-ACT Art. 10 "Training data provenance", Art. 13(3)(d)
  "Explanation method", Art. 14(4)(e) "Stop capability", NIST-AI-RMF
  MEASURE 2.2/2.7 …). Deterministic regex/keyword analyzer produces
  {present | partial | gap} × {info | warning | blocker} verdicts with the
  first matching excerpt from the document as evidence.
- `orchestrator/ingest.py` — single source of truth for artifact side
  effects (ingest_artifact_bytes / _base64 / _descriptor). Same code path
  from intake, JSON upload, and multipart upload.
- `orchestrator/citations.py::build_phase_citations` — now returns
  document_gaps; verdict escalation merges gap-analysis signal into citation
  verdicts (blocker gap ⇒ fail, warning gap ⇒ warning).
- `orchestrator/pipeline.py::_persist_phase` — rolls up blocker-severity gaps
  into phase blockers (code `DOC_GAP_<PHASE>`) and embeds
  `documentGaps` + `documentGapSummary` in the phase outputs BEFORE the
  integrity hash is computed, so the hash chain covers the gap findings.
- `orchestrator/routes.py` — new endpoints:
  - `POST /api/v1/runs/{id}/artifacts/upload` (multipart file, 20 MB max)
  - `POST /api/v1/runs/{id}/artifacts` now accepts `contentBase64` per artifact
  - `GET /api/v1/artifacts/{id}` (full extracted text + gap findings)
  - `GET /api/v1/runs/{id}` now returns `gaps[]`
- `mcp-server/ui/workbench.js` — file upload input in the intake artifact
  editor; new "Document gaps" KPI card on run detail; new "Extraction" +
  "Gap score" columns on the artifact table; per-phase document-gap section
  in the timeline showing each expected sub-article, its verdict, and the
  matching excerpt from the uploaded document.
- `orchestrator/requirements.txt` — pypdf>=6.0, python-multipart>=0.0.20.
- `DEPLOYMENT.md` — deployment guide (Docker Compose, env vars, migrations
  002/003/004, backup/restore, security hardening checklist).
- `tests/governance/test_gap_analysis.py` — 7 tests: well-formed DPIA has
  no blocker gaps, BAD DPIA (missing "measures envisaged") triggers
  blocker gap on GDPR Art. 35(7)(d) AND blocks the data_protection phase,
  multipart upload computes sha256, PDF via pypdf extracts + analyzes,
  bias-test JSON without DI triggers blocker gap, artifact text endpoint.

**Verification**: Testing agent iteration 3 signed off 100% backend / 100%
frontend. 28/28 python E2E + 52/52 vitest = 80 tests total, all passing.
P1 fix verified via 3 vitest regression tests + testing-agent HTTP walk of
the full session lifecycle against port 3000.

## 2026-02 iteration — Auditor Workbench UI + evidence-artifact citations
User asked "can I have a user-friendly tool for auditing?" with an explicit follow-up:
every phase must show WHICH documents/artifacts were inspected against WHICH regulatory
article, the intake form/API must accept a set of documents/evidence per audit run, and the
same flow must be drivable by both a human auditor AND an AI agent via MCP.

Delivered:
- `store/migrations/003_artifacts.sql` — governance_artifacts + governance_phase_citations.
- `store/artifacts.py` — insert/list/get_by_type + insert/list citations.
- `orchestrator/citations.py` — PHASE_EXPECTATIONS matrix (25 artifact-type ↔ article ↔
  control mappings across 8 phases with framework, article, control, and a deterministic
  verdict mapper: present | pass | warning | fail | missing).
- `orchestrator/pipeline.py` — _persist_phase now calls build_phase_citations, embeds
  `citedArtifacts`, `missingArtifacts`, `articleCitations` in every phase's outputs
  BEFORE integrity_hash is computed (evidence carries the citation chain).
- `orchestrator/routes.py` — IntakeRequest gains `evidenceArtifacts[]`; new endpoints:
  GET /runs (list, filter by modelId/status), GET /runs/{id} (now returns artifacts+citations
  arrays), POST /runs/{id}/artifacts (append), GET /runs/{id}/artifacts, GET /certificates
  (list), POST /certificates/{id}/revoke.
- `mcp-server/src/governance-tools.ts` — intake_register MCP tool schema now accepts
  `evidenceArtifacts[]` so AI agents produce identical evidence chains.
- `mcp-server/src/index.ts` — validateOrigin scoped to /mcp routes only; new routes:
  GET / (SPA shell), /assets/workbench.js, /assets/workbench.css, /status (old page kept).
- `mcp-server/src/workbench.ts` + `mcp-server/ui/workbench.js` + `.css` — full auditor
  workbench SPA (~1100 lines vanilla JS + ~300 lines CSS, no CDN, no build step):
  - #/login: 4 role cards (governance-admin, intake-officer, audit-engineer,
    certification-officer) + custom clientId/secret. Guest mode allowed for #/verify.
  - #/dashboard: 4 infra cards + recent runs + recent certs.
  - #/audit/new: 9-step wizard with role-based per-phase forms, inline artifact editor
    (18 default demo artifacts covering every PHASE_EXPECTATIONS entry), and a
    "Run full demo audit" button that chains phases 1-9 in one click.
  - #/runs, #/runs/:id: run detail with 4 KPIs (phases/artifacts/citations/missing),
    9-phase timeline (hash chain + article citations + engine outputs + blockers +
    "Missing evidence — controls not covered"), and an evidence artifact table.
  - #/certificates, #/certificates/:id: VC 2.0 viewer with verification checks + revoke.
  - #/verify (public, guest ok): paste URN → Ed25519 verify.
  - #/events: recent + dead-letter tables.
  - #/reaudit: trigger impact-scoped reaudit.
  - #/mcp: curl examples + 11 governance MCP tools list.
- tests/governance/test_artifacts_and_citations.py — 6 new E2E tests all passing.

Verification: 16/16 python E2E tests pass, 49/49 typescript tests pass, testing agent
signed off with 100% backend / ~95% frontend (only fix required was allowing #/verify as
a guest route — fixed). Preview URL:
https://1567e779-1049-4657-9026-42f6c3b7ffe1.preview.emergentagent.com

## Local infra (preview pod)
PostgreSQL (apt, user governance/governance_secret, db evidence_store, sql/init.sql +
governance migration applied at startup), Redis (daemonized :6379), Neo4j 5 (apt,
neo4j/governance_secret, started via `neo4j start`). After pod restart: `service postgresql
start; redis-server --daemonize yes; neo4j start` then restart supervisor backend/frontend.

## Backlog / next
- DONE (2026-02, part 4): security-fix test-suite refactor (env-sourced
  CREDS from conftest.py) + Emergent-managed Google Sign-In flow
  (workbench "Sign in with Google" button, backend
  `/api/v1/auth/google/session|me|logout`, HttpOnly cookie + governance JWT,
  Google-authenticated users → `governance-admin`).
- DONE (2026-02, part 3): data-testid coverage across the SPA + artifact
  detail modal wired to `GET /api/v1/artifacts/{id}` + null-guards on stale
  async render callbacks + supervisor adoption of Postgres/Neo4j/Redis so
  the data plane survives pod restarts.
- DONE (2026-02, part 2): P1 bug fix (MCP session lifecycle) + rich artifact
  ingest (multipart PDF/CSV/JSON/MD/TXT, server-side sha256, pypdf) +
  deterministic gap analysis producing article-level "which section of which
  document evidences (or fails to evidence) which sub-article" diagnostics +
  DEPLOYMENT.md.
- DONE (2026-02): Auditor Workbench SPA + article-level artifact citations.
- Backlog (deferred by user until legal-grade production push): CI workflow
  running compose stack + governance E2E on every push; NATS option for the
  event fabric; RFC 3161 timestamp anchoring for VC 2.0 certificates.
- Backlog (future enhancement to gap analysis): plug in an on-prem LLM-free
  NER pass for artifact types that don't lend themselves to regex (e.g.
  extracting explicit retention days, DPO email, dataset row counts).
- Backlog (workbench polish): per-organisation override file
  (`/app/config/gap_overrides.yml`) so compliance teams can tune the
  SPECIFICATIONS matrix without a code change — add company-specific
  required sections, tighten severities, layer regional overlays (DPDP,
  CCPA) on top of GDPR.