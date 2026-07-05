# Hacker News - Show HN Post

## Title
Show HN: ComplianceStack – Open-source MCP server for AI compliance auditing (EU AI Act, GDPR, NIST)

## URL
https://github.com/nyayoshbharuchanb15-max/ComplianceStack

## Comment
Hey HN!

I've been working on a project to help organizations navigate the rapidly evolving AI regulatory landscape.

With the EU AI Act now in law, GDPR enforcement increasing, and India's DPDP Act being implemented, AI teams need practical tools to ensure compliance.

ComplianceStack is an open-source MCP (Model Context Protocol) server that audits AI models against 5 regulatory frameworks in real-time.

**What it does:**
- 17-phase audit pipeline covering EU AI Act, NIST AI RMF, ISO 42001, GDPR, and India DPDP Act
- Native MCP integration with Claude Desktop, Cursor, Windsurf
- Zero data egress - all operations run on-premise
- BLOCKER FAIL mechanism that prevents certification of non-compliant models
- W3C Verifiable Credentials for cryptographically signed audit certificates

**Technical highlights:**
- TypeScript MCP server with Model Context Protocol SDK
- Python FastAPI backend for audit logic
- PostgreSQL + Neo4j + Redis for data storage
- Docker orchestration for easy deployment
- Fairlearn for bias assessment
- Evidently AI for drift detection

**Quick start:**
```
git clone https://github.com/nyayoshbharuchanb15-max/ComplianceStack.git
cd ComplianceStack
cp .env.example .env
docker compose up --build -d
```

**Why MCP?**
The Model Context Protocol allows AI assistants to directly invoke audit tools. This means you can ask Claude to run a full compliance audit on your model and get instant feedback in your IDE.

**Open questions:**
1. What other regulatory frameworks should we add?
2. How do you handle compliance for local LLMs?
3. Would you use this in production?

The code is open-source under the Apache 2.0 license.

Would love to get feedback from the HN community!
