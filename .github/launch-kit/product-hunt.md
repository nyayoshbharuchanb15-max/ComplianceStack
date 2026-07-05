# Product Hunt Launch

## Tagline
The first open-source MCP server that audits AI models against 5 regulatory frameworks in real-time

## Description
ComplianceStack is an enterprise-grade AI compliance platform that helps organizations audit their AI models against multiple regulatory frameworks.

### The Problem
AI regulation is here. The EU AI Act is law, GDPR fines are increasing, and India's DPDP Act is being enforced. Organizations need to ensure their AI models are compliant - or face significant fines.

### The Solution
ComplianceStack is a 17-phase audit pipeline that plugs directly into your AI assistant (Claude Desktop, Cursor, Windsurf) via the Model Context Protocol.

### Key Features
- **17-Phase Audit Pipeline:** EU AI Act, GDPR, NIST AI RMF, ISO 42001, India DPDP Act
- **MCP Integration:** Works with Claude Desktop, Cursor, Windsurf
- **Zero Data Egress:** All operations run on-premise
- **BLOCKER FAIL:** Prevents certification of non-compliant models
- **W3C Verifiable Credentials:** Cryptographically signed audit certificates
- **Open Source:** Apache 2.0 license

### How It Works
1. Clone the repo
2. `docker compose up --build -d`
3. Connect Claude Desktop
4. Ask: "Run a full audit on my model"
5. Get instant compliance feedback

### Technical Details
- TypeScript MCP server with Model Context Protocol SDK
- Python FastAPI backend for audit logic
- PostgreSQL + Neo4j + Redis for data storage
- Fairlearn for bias assessment
- Evidently AI for drift detection

### Who Is This For?
- AI/ML teams deploying models in regulated industries
- Compliance officers navigating AI regulation
- Open-source contributors interested in AI governance
- Organizations implementing responsible AI practices

### Why We Built This
We saw that existing GRC tools were:
- Slow and batch-oriented
- Cloud-dependent
- Expensive and proprietary
- Disconnected from AI development workflows

We wanted to build something that:
- Provides real-time feedback
- Runs completely on-premise
- Is open-source and free
- Integrates with modern AI development tools

### What's Next?
- Additional regulatory frameworks
- More AI assistant integrations
- Enhanced reporting and analytics
- Community-driven features

## Maker Comment
Hey Product Hunt! 👋

I'm excited to share ComplianceStack with you today.

As someone working in AI, I've seen firsthand how challenging it can be to navigate the rapidly evolving regulatory landscape. The EU AI Act, GDPR, NIST AI RMF - there are so many frameworks to consider.

I built ComplianceStack to make AI compliance easier and more accessible. It's a 17-phase audit pipeline that plugs directly into your AI assistant via the Model Context Protocol.

The key differentiators:
- **Real-time:** Get instant feedback in your IDE
- **Private:** Zero data egress - everything runs on-premise
- **Comprehensive:** 17 phases covering 5 regulatory frameworks
- **Open Source:** Apache 2.0 license

I'd love to get your feedback! What regulatory frameworks would you like to see added next? How are you handling AI compliance in your organization?

GitHub: https://github.com/nyayoshbharuchanb15-max/ComplianceStack

Thanks for checking it out! 🙏
