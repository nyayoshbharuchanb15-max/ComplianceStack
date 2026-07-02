# ComplianceStack — AI Governance Platform

**Enterprise-grade AI compliance and governance platform with zero-data-egress auditing with zero-data-egress auditing** — EU AI Act, NIST AI RMF, ISO/IEC 42001, GDPR, India DPDP Act

[![CI](https://github.com/nyayoshbharuchanb15-max/ComplianceStack/actions/workflows/ci.yml/badge.svg)](https://github.com/nyayoshbharuchanb15-max/ComplianceStack/actions)
[![License](https://img.shields.io/badge/license-dual--commercial-blue)](./LICENSE.md)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![Node 20](https://img.shields.io/badge/node-20-green)](https://nodejs.org)

---

## What This Is

An **enterprise-grade AI governance platform** that provides zero-data-egress compliance auditing for AI models across 5 regulatory frameworks. Integrates with any MCP-compatible AI assistant (Claude Desktop, Cursor, Windsurf, etc.) and executes a comprehensive 17-phase audit pipeline with BLOCKER FAIL protection.

## Regulatory Coverage

| Framework | Articles/Clauses | Status |
|-----------|-----------------|--------|
| **EU AI Act** (Reg. 2024/1689) | Art. 5, 6, 10, 12, 14, 15, Annex I–III | Implemented |
| **NIST AI RMF** (AI 100-1) | MAP 1.1, GOVERN 1.2, GOVERN 3.2, MEASURE 1.3, 2.2, 3.3, 4.1 | Implemented |
| **ISO/IEC 42001:2023** | Clauses 6.1, 6.2, 7.4.3, 7.5, 8.1.2, 8.1.3, 8.2, 9.1 | Implemented |
| **GDPR** (Reg. 2016/679) | Art. 5, 9, 22, 25, 30, 35, 44–49 | Implemented |
| **India DPDP Act 2023** | Sec. 5–14 (Consent, Fiduciary, Processor, Principal rights) | Implemented |

## Architecture

```
┌──────────────────────┐     ┌──────────────────────────────────────────────┐
│   AI Assistant       │     │         AI Governance MCP Server             │
│  (Claude Desktop,    │◄───►│                                              │
│   Cursor, etc.)      │     │  TypeScript MCP Server        Python Backend │
│                      │     │  ┌──────────────────┐     ┌───────────────┐  │
│                      │     │  │ 17 MCP Tools      │────►│ FastAPI        │  │
│                      │     │  │ (Risk, Bias,      │     │ (Audit Logic)  │  │
│                      │     │  │  DPIA, Drift...)  │     │               │  │
│                      │     │  └──────────────────┘     └───────┬───────┘  │
│                      │     │         │                         │          │
│  ┌────────────────┐  │     └─────────┼─────────────────────────┼──────────┘
│  │  OAuth 2.1 +   │  │               │                         │
│  │  RBAC          │  │  ┌────────────┼─────────────────────────┼──────────┐
│  └────────────────┘  │  │            │       Data Layer        │          │
│                      │  │            ▼                         ▼          │
│  Zero Egress ────────┤  │ ┌──────────────┐ ┌──────────────┐ ┌─────────┐  │
│  On-Premise ─────────┤  │ │  PostgreSQL  │ │    Neo4j     │ │  Redis  │  │
│                      │  │ │  Evidence    │ │  Provenance  │ │ Streams │  │
│                      │  │ │  Store +     │ │  Graph +     │ │(Re-audit│  │
│                      │  │ │  Merkle Tree │ │  Discovery   │ │ Events) │  │
│                      │  │ └──────────────┘ └──────────────┘ └─────────┘  │
│                      │  └────────────────────────────────────────────────┘
└──────────────────────┘
```

## 17-Phase Audit Pipeline

| Phase | Tool | What It Does | Regulatory Mapping |
|-------|------|-------------|-------------------|
| 1 | `classify_ai_risk` | EU AI Act risk tier classification (Prohibited → Minimal) | Art. 6, Annex I–III |
| 2 | `discover_supply_chain` | Filesystem crawler populates Neo4j provenance graph | Art. 10, ISO 7.4.3 |
| 3 | `audit_supply_chain` | Neo4j graph query for data lineage & IP clearance | Art. 10, 12 |
| 4 | `verify_human_oversight` | HITL/kill-switch verification (BLOCKER FAIL if missing) | Art. 14, GDPR Art. 22 |
| 5 | `run_bias_assessment` | Fairlearn metrics: demographic parity, equal opportunity, disparate impact | Art. 10, GDPR Art. 9, 35 |
| 6 | `generate_dpia` | GDPR Art. 35 DPIA with cross-border transfer analysis | Art. 5, 9, 22, 35, 44–49 |
| 7 | `run_adversarial_tests` | Prompt injection, jailbreak, OOD, model inversion, membership inference | Art. 15 |
| 8 | `score_audit_weighted` | Aggregate score (0–100), BLOCKER FAIL halts certification | NIST MEASURE 4.1 |
| 9 | `generate_audit_certificate` | W3C Verifiable Credential (Ed25519-signed) issued | W3C VC 1.1, ISO 7.5 |
| 10 | `monitor_model_drift` | Evidently AI drift detection, auto re-audit via Redis Streams | Art. 15, ISO 9.1 |
| 11 | `audit_session_memory` | STM/LTM isolation, context window limits, wipe-on-expiry | GDPR Art. 5(1)(f), DPDP Sec. 8 |
| 12 | `audit_rag_quality` | Retrieval accuracy, embedding bias, freshness, hallucination rate | Art. 15, NIST MEASURE 3.3 |
| 13 | `audit_prompt_templates` | Injection surface, few-shot bias, instruction safety | Art. 10, 13, NIST GOVERN 1.2 |
| 14 | `audit_agent_trust` | Agent identity, P2P integrity, collusion detection | Art. 12, 14, DPDP Sec. 8 |
| 15 | `audit_tool_permissions` | Privilege escalation, unauthorized access, permission drift | DPDP Sec. 8, GDPR Art. 25 |
| 16 | `classify_agent_autonomy` | Assistive → Fully Autonomous classification (BLOCKER if uncontrolled) | Art. 6, 14, NIST GOVERN 3.2 |

## Quick Start

### Prerequisites

- Docker 24+ and Docker Compose v2
- Git

### 1. Clone and Start

```bash
git clone https://github.com/nyayoshbharuchanb15-max/ComplianceStack.git
cd ComplianceStack
cp .env.example .env
docker compose up --build -d
```

### 2. Verify Services

```bash
curl http://localhost:8000/health
# {"status":"ok","services":{"postgres":"connected","neo4j":"connected","redis":"connected","auth":"enabled"}}
```

### 3. Connect an MCP Client

#### Claude Desktop (Stdio)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "compliance-stack": {
      "command": "docker",
      "args": ["exec", "-i", "ai-governance-mcp", "node", "dist/index.js"],
      "env": { "PYTHON_BACKEND_URL": "http://python-backend:8000" }
    }
  }
}
```

#### Cursor / Windsurf (SSE)

```json
{
  "mcpServers": {
    "compliance-stack": {
      "url": "http://localhost:3000/sse"
    }
  }
}
```

#### MCP Inspector (Testing)

```bash
npx @modelcontextprotocol/inspector http://localhost:3000/sse
```

### 4. Run an Audit

Ask your AI assistant:

```
"Run a full 9-phase audit on model 'my-model-v1'. 
 Classify it as a general-purpose AI used in employment 
 with profiling capabilities, no kill-switch, 
 sensitive features: ['race', 'gender', 'age'], 
 data controller: 'Acme Corp', DPO: 'Jane Doe'."
```

## API Reference

### Python Backend Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/api/auth/token` | OAuth 2.1 token issuance |
| POST | `/api/risk/classify` | Phase 1: Risk classification |
| POST | `/api/supply-chain/discover` | Phase 2: Auto-discover models/datasets |
| POST | `/api/supply-chain/audit` | Phase 3: Supply chain audit |
| POST | `/api/human-oversight/verify` | Phase 4: Human oversight |
| POST | `/api/bias/assess` | Phase 5: Bias assessment |
| POST | `/api/dpia/generate` | Phase 6: DPIA generation |
| POST | `/api/adversarial/run` | Phase 7: Adversarial testing |
| POST | `/api/scoring/weighted` | Phase 8: Weighted scoring |
| POST | `/api/certificate/generate` | Phase 9: VC certificate |
| POST | `/api/drift/monitor` | Phase 10: Drift monitoring |
| POST | `/api/dpdp/assess` | India DPDP Act compliance |
| POST | `/api/ropa/generate` | GDPR Art. 30 ROPA |
| POST | `/api/dsar/process` | GDPR Art. 15–17 DSAR/Erasure |
| POST | `/api/session-memory/audit` | Session memory isolation audit |
| POST | `/api/rag-quality/evaluate` | RAG quality evaluation |
| POST | `/api/prompt-audit/evaluate` | Prompt template safety audit |
| POST | `/api/agent-trust/evaluate` | Agent trust verification |
| POST | `/api/tool-permissions/evaluate` | Tool permission boundary audit |
| POST | `/api/agent-autonomy/classify` | Agent autonomy classification |

## MCP Tools

| Tool | Parameters | Returns |
|------|-----------|---------|
| `classify_ai_risk` | `modelId`, `modelType`, `sector` | Risk tier + rationale |
| `discover_supply_chain` | `modelId`, `modelSearchPaths?`, `dataSearchPaths?` | Discovery summary |
| `audit_supply_chain` | `modelId`, `deepScan?` | Provenance report |
| `verify_human_oversight` | `modelId`, `hasHumanInTheLoop`, `hasKillSwitch`, `deploymentContext` | Oversight certificate |
| `run_bias_assessment` | `modelId`, `datasetSample`, `sensitiveFeatures`, `fairnessThreshold?` | Bias report |
| `generate_dpia` | `modelId`, `dataController`, `dpoName`, `processingPurpose`, `dataCategories` | DPIA report |
| `run_adversarial_tests` | `modelId`, `testSuites`, `severityThreshold?` | Adversarial report |
| `score_audit_weighted` | `modelId`, all phase results | Weighted score + BLOCKER check |
| `generate_audit_certificate` | `modelId`, `weightedScore`, `tier`, `compliant`, `issuerName` | W3C VC-JSON |
| `monitor_model_drift` | `modelId`, `referenceData`, `productionData`, `features` | Drift report |
| `assess_dpdp_compliance` | `modelId`, `dataFiduciary` | DPDP Act compliance report |
| `audit_session_memory` | `modelId`, `sessionId`, `stmConfig`, `ltmConfig?`, `isolationLevel` | Memory isolation audit |
| `audit_rag_quality` | `modelId`, `vectorDbConfig`, `sampleQueries`, `freshnessPolicyDays?` | RAG quality report |
| `audit_prompt_templates` | `modelId`, `promptTemplates`, `fewShotExamples?`, `systemPrompt?` | Prompt safety audit |
| `audit_agent_trust` | `modelId`, `agents`, `messageBusConfig?`, `p2pEnabled?` | Agent trust report |
| `audit_tool_permissions` | `modelId`, `toolRegistry`, `accessLogs` | Permission boundary report |
| `classify_agent_autonomy` | `modelId`, `agentType`, `hasHumanOversight`, `canMakeDecisions` | Autonomy classification |

## W3C Verifiable Credentials

Audit certificates are issued as W3C VCs with Ed25519 cryptographic proof:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
  "id": "urn:uuid:...",
  "type": ["VerifiableCredential", "AIAuditCertificate"],
  "issuer": { "id": "did:web:governance.internal:...", "name": "..." },
  "credentialSubject": {
    "modelId": "model-llm-v2",
    "auditScore": 92.5,
    "tier": "limited",
    "compliant": true
  },
  "proof": { "type": "Ed25519Signature2020", "proofValue": "z..." }
}
```

## Security

- **Zero data egress** — all operations in-process, no external API calls
- **OAuth 2.1 + RBAC** — admin, auditor, viewer roles with scoped endpoints
- **PII redaction** — middleware intercepts and redacts PII from all API responses
- **Ed25519 signing** — keys never leave the container
- **Merkle audit trail** — tamper-evident evidence chain
- **On-premise only** — no telemetry, no external dependencies

## Development

```bash
# Python backend
cd python-backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# MCP server (in another terminal)
cd mcp-server
npm install
npm run dev

# Tests
cd python-backend && pytest tests/
cd mcp-server && npm test
```

## License

**Dual License** — Copyright © 2026 Nyayosh Bharuchanb15-Max.

| Use Case | License | Royalty |
|----------|---------|---------|
| Non-commercial (personal, academic, research, non-profit) | Free | None |
| Commercial (under $500K revenue) | Starter | 5% of gross revenue |
| Commercial ($500K+ revenue) | Enterprise | 10% of gross revenue |

See [LICENSE.md](./LICENSE.md) for complete terms.

### Intellectual Property

All code, documentation, trademarks ("ComplianceStack"), and associated
IP are the exclusive property of the copyright holder. Contributions are accepted
under the terms of the [Developer Certificate of Origin](./CONTRIBUTING.md).
