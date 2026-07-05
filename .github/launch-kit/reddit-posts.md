# Reddit Posts

## Post 1: r/MachineLearning

**Title:** [P] ComplianceStack: Open-source MCP server for AI compliance auditing across 5 regulatory frameworks

**Body:**

Hey r/MachineLearning!

I've been working on an open-source project that I think could be valuable for teams deploying AI models in production.

**The Problem:**
With the EU AI Act now in law, GDPR enforcement increasing, and India's DPDP Act being implemented, AI teams need to ensure their models are compliant. Traditional GRC tools are slow, cloud-dependent, and don't integrate well with modern AI workflows.

**The Solution: ComplianceStack**
An enterprise-grade MCP (Model Context Protocol) server that audits AI models against 5 regulatory frameworks in real-time.

**Key Features:**
- 17-phase audit pipeline covering EU AI Act, NIST AI RMF, ISO 42001, GDPR, and India DPDP Act
- Native MCP integration with Claude Desktop, Cursor, Windsurf
- Zero data egress - all operations run on-premise
- BLOCKER FAIL mechanism that prevents certification of non-compliant models
- W3C Verifiable Credentials for cryptographically signed audit certificates
- Fairlearn-based bias assessment
- Adversarial robustness testing (prompt injection, jailbreak, OOD)

**Tech Stack:**
- TypeScript MCP Server with Model Context Protocol SDK
- Python FastAPI backend for audit logic
- PostgreSQL + Neo4j + Redis for data storage
- Docker orchestration

**Quick Start:**
```bash
git clone https://github.com/nyayoshbharuchanb15-max/ComplianceStack.git
cd ComplianceStack
cp .env.example .env
docker compose up --build -d
```

Would love to get feedback from the community! What regulatory frameworks would you like to see added next?

GitHub: https://github.com/nyayoshbharuchanb15-max/ComplianceStack

---

## Post 2: r/LocalLLaMA

**Title:** [Discussion] How are you handling AI compliance for local LLMs? We built an open-source solution.

**Body:**

Fellow LocalLLaMA enthusiasts!

With more people running local LLMs for production use cases, I'm curious - how are you handling compliance requirements?

For those deploying in regulated industries (healthcare, finance, employment), you need:
- EU AI Act risk classification
- Bias assessment across protected attributes
- Human oversight verification
- Audit trails

We built **ComplianceStack** - an open-source MCP server that audits AI models against 5 regulatory frameworks.

**Why this matters for LocalLLaMA:**
- Works with local models (no data leaves your machine)
- MCP integration with Claude Desktop, Cursor
- 17-phase audit pipeline
- W3C Verifiable Credentials for compliance proof
- Zero data egress - completely on-premise

**Quick demo:**
1. Clone the repo
2. `docker compose up --build -d`
3. Connect Claude Desktop
4. Ask: "Run a full audit on my local model"

The audit covers:
- Risk classification (EU AI Act)
- Supply chain provenance
- Human oversight verification
- Bias assessment (Fairlearn)
- DPIA generation (GDPR)
- Adversarial robustness testing
- And more...

GitHub: https://github.com/nyayoshbharuchanb15-max/ComplianceStack

Would love to hear how others are handling compliance for local deployments!

---

## Post 3: r/Python

**Title:** [Project] ComplianceStack: Open-source AI compliance auditing platform built with FastAPI

**Body:**

Hi r/Python!

I wanted to share a project I've been working on - **ComplianceStack**, an enterprise-grade AI compliance platform built with Python.

**What it does:**
Audits AI models against 5 regulatory frameworks (EU AI Act, NIST AI RMF, ISO 42001, GDPR, India DPDP Act) with a 17-phase audit pipeline.

**Python Features:**
- FastAPI backend with async support
- SQLAlchemy + Alembic for database migrations
- Pydantic for data validation
- Fairlearn for bias assessment
- Evidently AI for drift detection
- Cryptographic signing with Ed25519
- OAuth 2.1 + RBAC authentication

**Architecture:**
```
Python Backend (FastAPI) ←→ TypeScript MCP Server ←→ AI Assistant (Claude/Cursor)
         ↓
   PostgreSQL + Neo4j + Redis
```

**Quick Start:**
```bash
git clone https://github.com/nyayoshbharuchanb15-max/ComplianceStack.git
cd ComplianceStack/python-backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

**Testing:**
```bash
pytest tests/ -v
ruff check .
mypy .
```

Would appreciate any feedback or contributions!

GitHub: https://github.com/nyayoshbharuchanb15-max/ComplianceStack

---

## Post 4: r/technology

**Title:** The EU AI Act is now law. Here's an open-source tool to ensure your AI models are compliant.

**Body:**

The EU AI Act became law in August 2024, and enforcement is ramping up. Organizations deploying AI systems in the EU need to ensure compliance or face significant fines.

I've been working on **ComplianceStack** - an open-source AI compliance platform that helps organizations audit their AI models against multiple regulatory frameworks.

**What it covers:**
- EU AI Act (risk classification, human oversight, bias)
- GDPR (DPIA, ROPA, DSAR)
- NIST AI RMF (risk management framework)
- ISO/IEC 42001 (AI management system)
- India DPDP Act (data protection)

**Key features:**
- 17-phase audit pipeline
- Works with Claude Desktop, Cursor via MCP
- Zero data egress - completely on-premise
- W3C Verifiable Credentials for compliance proof
- BLOCKER FAIL mechanism prevents non-compliant deployments

**Why this matters:**
- AI regulation is here, and organizations need to comply
- Traditional GRC tools are slow and expensive
- This is open-source under the Apache 2.0 license

GitHub: https://github.com/nyayoshbharuchanb15-max/ComplianceStack

What do you think? Is this useful for organizations navigating AI compliance?
