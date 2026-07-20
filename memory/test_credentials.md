# Test credentials — AI Governance MCP Server

## Governance orchestrator service accounts (client credentials → JWT)
Token endpoint: POST {BASE}/api/v1/auth/token  body: {"clientId": "...", "clientSecret": "..."}
Preview BASE: http://localhost:8001 (external: https://1567e779-1049-4657-9026-42f6c3b7ffe1.preview.emergentagent.com)
Docker compose BASE: http://localhost:8010

| clientId | clientSecret | role | scopes |
|---|---|---|---|
| governance-admin | govern-admin-secret-dev | governance-admin | all |
| intake-officer | intake-officer-secret-dev | intake-officer | phase:intake, phase:scope, runs:read |
| audit-engineer | audit-engineer-secret-dev | audit-engineer | phase:risk/privacy/fairness/robustness/explainability, runs:read |
| certification-officer | certification-officer-secret-dev | certification-officer | phase:certify, phase:monitor, reaudit:trigger, runs:read, certs:read |

Use header: Authorization: Bearer <accessToken>

## Endpoints
- Phases: POST /api/v1/phases/{intake|scope|risk|data-protection|fairness|robustness|explainability|certification|monitoring}
- Reaudit: POST /api/v1/reaudit ; Runs: GET /api/v1/runs, GET /api/v1/runs/{runId} (+/lineage +/artifacts)
- Artifacts: POST /api/v1/runs/{runId}/artifacts, GET /api/v1/runs/{runId}/artifacts
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
