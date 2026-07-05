# LinkedIn Launch Post

## Post

🚨 **AI regulation is here. Are your models compliant?**

The EU AI Act became law in August 2024. GDPR fines exceeded €2 billion in 2024. India's DPDP Act is being enforced.

Organizations deploying AI systems need to ensure compliance - or face significant fines and reputational damage.

I'm excited to announce **ComplianceStack** - an open-source AI compliance platform that helps organizations audit their AI models against 5 regulatory frameworks.

### What ComplianceStack does:

✅ **17-phase audit pipeline** covering:
- EU AI Act (risk classification, human oversight, bias)
- GDPR (DPIA, ROPA, DSAR)
- NIST AI RMF (risk management framework)
- ISO/IEC 42001 (AI management system)
- India DPDP Act (data protection)

✅ **Native MCP integration** with Claude Desktop, Cursor, Windsurf
✅ **Zero data egress** - all operations run on-premise
✅ **BLOCKER FAIL mechanism** prevents non-compliant deployments
✅ **W3C Verifiable Credentials** for cryptographically signed audit certificates

### Why this matters:

Traditional GRC tools are:
- Slow and batch-oriented
- Cloud-dependent (data leaves your infrastructure)
- Expensive and proprietary
- Disconnected from AI development workflows

ComplianceStack is:
- Real-time feedback in your IDE
- Completely on-premise
- Open-source under the Apache 2.0 license
- Integrated with modern AI development tools

### Technical highlights:

- TypeScript MCP server with Model Context Protocol SDK
- Python FastAPI backend for audit logic
- PostgreSQL + Neo4j + Redis for data storage
- Fairlearn for bias assessment
- Evidently AI for drift detection
- Ed25519 cryptographic signing

### Quick start:

```bash
git clone https://github.com/nyayoshbharuchanb15-max/ComplianceStack.git
cd ComplianceStack
cp .env.example .env
docker compose up --build -d
```

### Get involved:

The code is open-source and we welcome contributions!

🔗 GitHub: https://github.com/nyayoshbharuchanb15-max/ComplianceStack

What regulatory frameworks would you like to see added next? How are you handling AI compliance in your organization?

#AIGovernance #EUAIAct #GDPR #AICompliance #MachineLearning #OpenSource #RegulatoryCompliance #NIST #ISO42001 #DataPrivacy #AISafety
