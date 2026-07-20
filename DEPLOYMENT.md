# Deployment guide — AI Governance MCP Server

This guide describes how to deploy the AI Governance MCP Server in a **fully
on-premise / air-gapped** environment (the target deployment mode — no outbound
API calls are permitted for regulated workflows).

All state is kept in three local databases: PostgreSQL (evidence store),
Neo4j (control-graph lineage) and Redis (event fabric).

---

## 1. Deployment options

| Mode | Best for | How |
|------|----------|-----|
| **Docker Compose** | Production, staging, on-prem | `docker compose up -d` — bundles all six services on a single host. |
| **Kubernetes (manifest)** | Multi-tenant, HA | Adapt the compose file into a Helm chart; each service is a stateless Deployment (except the DBs). |
| **Bare metal / apt** | Air-gapped labs (current preview) | Install PostgreSQL, Neo4j, Redis natively; run the orchestrator via `uvicorn`/`supervisor` and the MCP server via `node`. |

The preview pod uses the bare-metal mode (see `PRD.md`).

---

## 2. Prerequisites

- Linux host (tested on Debian 12 / Ubuntu 22.04)
- Docker Engine ≥ 24 + Docker Compose plugin (for the compose flow)
- OR: PostgreSQL ≥ 14, Neo4j ≥ 5, Redis ≥ 5, Python ≥ 3.11, Node ≥ 20 (for the bare-metal flow)
- Outbound network is **not required**. All Python + Node dependencies must be
  vendored beforehand in air-gapped environments (see § 6).

---

## 3. Docker Compose (recommended)

```bash
git clone <this repo> ai-governance && cd ai-governance
cp .env.example .env                # fill in the secrets (see § 4)
docker compose up -d
docker compose ps                    # confirm postgres, neo4j, redis, cert-signer,
                                     # orchestrator and mcp-server are healthy
```

The default compose stack exposes:

| Service          | Container port | Host port | Notes |
|------------------|---------------:|----------:|-------|
| orchestrator     | 8010           | 8010      | FastAPI orchestrator (JWT auth) |
| mcp-server       | 3010           | 3010      | MCP Streamable HTTP + Auditor Workbench UI |
| cert-signer      | 8020           | *(private)* | Ed25519 VC 2.0 signer — private-only network |
| postgres         | 5432           | *(private)* | Evidence store — no host port |
| neo4j            | 7687           | *(private)* | Bolt — no host port |
| redis            | 6379           | *(private)* | Event fabric — no host port |

Only the orchestrator and MCP server bind to host ports. All persistent state
lives in named volumes: `pg_data`, `neo4j_data`, `redis_data`.

### Smoke test

```bash
curl -s http://localhost:8010/api/v1/health | jq
TOKEN=$(curl -s -X POST http://localhost:8010/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"clientId":"governance-admin","clientSecret":"<from .env>"}' | jq -r .accessToken)
curl -s http://localhost:8010/api/v1/runs -H "Authorization: Bearer $TOKEN" | jq .
```

Open the Auditor Workbench at http://localhost:3010/.

---

## 4. Environment variables

All secrets and connection strings are supplied through environment variables —
never committed defaults. `.env.example` documents the required keys:

```
POSTGRES_USER=governance
POSTGRES_PASSWORD=<strong secret>
POSTGRES_DB=evidence_store
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<strong secret>

REDIS_URL=redis://redis:6379/0

# JWT signing secret for the orchestrator (HS256).
GOVERNANCE_JWT_SECRET=<32+ bytes of random>

# Client-credentials service accounts (comma-separated pairs).
# Rotate quarterly and enforce a stronger secret in production.
GOVERNANCE_CLIENTS=governance-admin:<secret>|governance-admin,intake-officer:<secret>|intake-officer,audit-engineer:<secret>|audit-engineer,certification-officer:<secret>|certification-officer

# Ed25519 signing key — kept in a bind-mounted secret file
CERT_SIGNER_SEED_PATH=/var/lib/governance/keys/ed25519.seed
CERT_SIGNER_URL=http://cert-signer:8020   # empty in preview → embedded

# MCP transport
MCP_TRANSPORT=streamable-http
MCP_HTTP_HOST=0.0.0.0
PORT=3010
GOVERNANCE_API_URL=http://orchestrator:8010
```

Copy `/app/.env.example` to `.env` and fill in strong secrets. Never commit
this file.

### Ed25519 signing key

The signer expects a 32-byte seed at `CERT_SIGNER_SEED_PATH`. Generate one:

```bash
mkdir -p /var/lib/governance/keys
python3 -c "import os,sys; sys.stdout.buffer.write(os.urandom(32))" \
  > /var/lib/governance/keys/ed25519.seed
chmod 600 /var/lib/governance/keys/ed25519.seed
```

Back this file up to your HSM / vault — losing it invalidates all issued
certificates.

---

## 5. Database migrations

Migrations are idempotent and run automatically at orchestrator startup. They
live in:

- `/app/store/migrations/*.sql`  — PostgreSQL
- `/app/graph/migrations/*.cypher` — Neo4j

Current PostgreSQL migrations:

| # | File | Purpose |
|---|------|---------|
| 002 | `002_governance.sql` | Core: runs, phase results, certificates, events, monitoring |
| 003 | `003_artifacts.sql` | Evidence artifacts + per-phase article citations |
| 004 | `004_gap_analysis.sql` | Extracted text + document gap findings |

To force a rerun (e.g. after restoring a backup): drop the corresponding tables
and restart the orchestrator; the migration runner will re-apply any missing
scripts.

---

## 6. Air-gapped / vendored dependencies

Because no outbound egress is allowed:

1. **Python** — vendor wheels once, then install offline:
   ```bash
   pip download -r orchestrator/requirements.txt -d vendor/py
   pip install --no-index --find-links=vendor/py -r orchestrator/requirements.txt
   ```
2. **Node** — commit the `mcp-server/package-lock.json` and use `yarn install --offline` after seeding
   the offline mirror (`yarn config set yarn-offline-mirror ./vendor/node`).
3. **Postgres / Neo4j / Redis** — pin the Docker image digests in `docker-compose.yml`
   and pre-pull them onto the target host.

The MCP server itself embeds no third-party service calls; the entire audit
pipeline runs on-CPU with deterministic engines + local databases.

---

## 7. Backup & restore

The evidence chain and certificates are cryptographically hash-linked; a
consistent snapshot requires a coordinated dump.

```bash
# Postgres
docker compose exec postgres pg_dump -U $POSTGRES_USER -Fc $POSTGRES_DB \
  > backups/evidence_store_$(date +%F).dump

# Neo4j (offline dump)
docker compose stop neo4j
docker compose run --rm neo4j neo4j-admin database dump neo4j \
  --to-path=/backups
docker compose start neo4j

# Redis (RDB snapshot)
docker compose exec redis redis-cli BGSAVE
docker compose cp redis:/data/dump.rdb backups/dump_$(date +%F).rdb

# Ed25519 seed (encrypt at rest)
gpg --symmetric /var/lib/governance/keys/ed25519.seed
```

Restore is the reverse. Because the run/phase/certificate hashes chain into
the Neo4j lineage, all three stores must be restored from the **same snapshot
timestamp** to preserve integrity.

---

## 8. Observability

- `GET /api/v1/health` — overall + per-service status (postgres, neo4j, redis, certSigner).
- `GET /api/v1/events/recent` — recent phase events on the Redis stream.
- `GET /api/v1/events/dead-letter` — poisoned events after 3 delivery attempts.
- Structured logs on stdout (orchestrator + mcp-server). Ship them to your
  SIEM via journald / Fluent Bit — no direct egress from the app.

---

## 9. Rolling upgrades

1. Read the release notes (`memory/PRD.md` + `CHANGELOG.md`) for schema changes.
2. Take a snapshot (§ 7).
3. Deploy the new orchestrator container. Migrations apply automatically.
4. Roll the mcp-server container.
5. Verify: `python -m pytest tests/governance -q` from the same host or run
   the `/api/v1/health` smoke test.

Because every phase output is deterministically hashed and chained, upgrades
that change engine outputs will produce different `integrityHash` values —
you should re-run in-flight audits on the new version and cross-reference
certificates by their `supersedes` link.

---

## 10. Security hardening checklist

- [ ] JWT secret ≥ 32 random bytes; rotated quarterly.
- [ ] Service-account passwords rotated on the same cadence.
- [ ] Ed25519 signing seed stored in an HSM / bind-mounted secret, not the repo.
- [ ] MCP `/mcp` endpoint reachable only from trusted network segments.
- [ ] MCP `MCP_ALLOWED_ORIGINS` set to the fully-qualified UI hostname.
- [ ] `postgres`, `neo4j`, `redis` NOT exposed to any host port — network-namespace only.
- [ ] Backup snapshots stored encrypted (age / gpg / KMS).
- [ ] Audit logs (structured JSON) shipped to an append-only SIEM.
- [ ] Regular reaudit trigger cadence configured for each certified model.
