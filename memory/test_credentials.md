# Test credentials — AI Governance MCP Server

## Governance orchestrator service accounts (client credentials → JWT)
Token endpoint: POST {BASE}/api/v1/auth/token  body: {"clientId": "...", "clientSecret": "..."}
Preview BASE: http://localhost:8001 (external: https://1567e779-1049-4657-9026-42f6c3b7ffe1.preview.emergentagent.com)
Docker compose BASE: http://localhost:8010

Client secrets are held in `/app/backend/.env` and supplied via env vars. They
are NEVER shipped in the workbench, printed by the status page, or committed
to this file. For local automation the fixtures below read them at runtime:

| clientId | env var holding the secret | role | scopes |
|---|---|---|---|
| governance-admin | `GOV_ADMIN_SECRET` | governance-admin | all incl. certs:revoke |
| intake-officer | `GOV_INTAKE_SECRET` | intake-officer | phase:intake, phase:scope, runs:read |
| audit-engineer | `GOV_AUDIT_SECRET` | audit-engineer | phase:risk/privacy/fairness/robustness/explainability, runs:read |
| certification-officer | `GOV_CERT_SECRET` | certification-officer | phase:certify, phase:monitor, reaudit:trigger, runs:read, certs:read, certs:revoke |

To read the current preview secret for a test run:

    export GOV_ADMIN_SECRET=$(grep '^GOV_ADMIN_SECRET' /app/backend/.env | cut -d'"' -f2)

The startup validator refuses to boot if any secret is unset, matches a
known-weak default (e.g. `govern-admin-secret-dev`), or is shorter than 24
characters.

Rotation guidance: generate a fresh secret with
`python3 -c "import secrets; print(secrets.token_urlsafe(32))"` and update
`/app/backend/.env`, then `sudo supervisorctl restart backend`.

Use header: Authorization: Bearer <accessToken>

## Endpoints
- Phases: POST /api/v1/phases/{intake|scope|risk|data-protection|fairness|robustness|explainability|certification|monitoring}
- Reaudit: POST /api/v1/reaudit ; Runs: GET /api/v1/runs, GET /api/v1/runs/{runId} (+/lineage +/artifacts)
- Artifacts: POST /api/v1/runs/{runId}/artifacts (JSON, optional contentBase64 per artifact),
  POST /api/v1/runs/{runId}/artifacts/upload (multipart file, 20 MB max),
  GET /api/v1/runs/{runId}/artifacts, GET /api/v1/artifacts/{artifactId} (extracted text + gap findings)
- Certs: GET /api/v1/certificates (list), GET /api/v1/certificates/{id}, POST /api/v1/certificates/{id}/revoke
- Certs (public): GET /api/v1/certificates/{id}/verify, /status
- Events: GET /api/v1/events/recent, /api/v1/events/dead-letter, POST /api/v1/events/test-dead-letter
- Health: GET /health, GET /api/v1/health
- Auditor Workbench SPA (port 3000): GET / (login → wizard/dashboard/runs/certs/events/reaudit),
  /assets/workbench.js, /assets/workbench.css. Guest mode allowed on #/verify only.

## Infra (preview pod)
- PostgreSQL: governance / governance_secret, db evidence_store, localhost:5432
- Neo4j: neo4j / governance_secret, bolt://localhost:7687
- Redis: redis://localhost:6379/0 (no auth)
- MCP server: stdio via `node /app/mcp-server/dist/index.js` (env GOVERNANCE_API_URL=http://localhost:8001);
  streamable-http on port 3000 (/health, /mcp)
- E2E: GOVERNANCE_API_URL=http://localhost:8001 python -m pytest tests/governance -v
- NOTE: uvicorn --reload only watches /app/backend — restart backend after orchestrator edits.

## Google Sign-In (Emergent-managed OAuth)
- **Frontend flow**: on `#/login` click `[data-testid="login-google-btn"]` → browser goes to `https://auth.emergentagent.com/?redirect=<origin>/` → after Google flow returns to `<origin>/#session_id=<id>` → SPA POSTs the id to `/api/v1/auth/google/session` → JWT returned + httpOnly cookie set.
- **Backend endpoints**:
  - `POST /api/v1/auth/google/session` — header `X-Session-ID: <id>` → 200 `{accessToken, role, scopes, clientId, user}` + `Set-Cookie: governance_session=...; HttpOnly; Secure; SameSite=None`
  - `GET /api/v1/auth/me` — via cookie or `Authorization: Bearer <session_token>` → 200 `{userId, email, name, picture, role, scopes, expiresAt}`
  - `POST /api/v1/auth/logout` — 204, deletes DB row + clears cookie
- **Test fixture escape hatch** (preview only, guarded by `GOV_ALLOW_TEST_AUTH=1`):
  - `GOOGLE_AUTH_TEST_SESSION_ID=test-fixture-session-id-abc123`
  - `GOOGLE_AUTH_TEST_SESSION_TOKEN=test-fixture-session-token-xyz789`
  - `GOOGLE_AUTH_TEST_EMAIL=test.user@governance.local`
  - Users signing in with the fixture ID are minted role `governance-admin` (full scopes).
- Role mapping: all Google-authenticated users → **governance-admin** (per user product decision).
