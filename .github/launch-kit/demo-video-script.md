# Demo Video Script

## Video Title
ComplianceStack: AI Compliance Auditing in 5 Minutes

## Video Length
5 minutes

## Script

### Opening (0:00 - 0:30)
[Screen: ComplianceStack logo and tagline]

**Narrator:**
"AI regulation is here. The EU AI Act is law, GDPR fines are increasing, and India's DPDP Act is being enforced. How do you ensure your AI models are compliant?

Meet ComplianceStack - the first open-source MCP server that audits AI models against 5 regulatory frameworks in real-time."

### Problem Statement (0:30 - 1:00)
[Screen: Statistics about AI regulation]

**Narrator:**
"Traditional GRC tools are slow, cloud-dependent, and disconnected from your AI development workflow. You need something that's fast, private, and integrated with the tools you already use."

### Solution Overview (1:00 - 1:30)
[Screen: Architecture diagram]

**Narrator:**
"ComplianceStack is a 17-phase audit pipeline that plugs directly into your AI assistant via the Model Context Protocol. It works with Claude Desktop, Cursor, and Windsurf.

Every audit runs 100% on-premise. Zero data leaves your infrastructure."

### Live Demo (1:30 - 3:30)
[Screen: Terminal and Claude Desktop]

**Narrator:**
"Let me show you how it works.

First, we clone the repository and start the services."

[Screen: Running commands]
```bash
git clone https://github.com/nyayoshbharuchanb15-max/ComplianceStack.git
cd ComplianceStack
cp .env.example .env
docker compose up --build -d
```

**Narrator:**
"Now let's verify the services are running."

[Screen: Health check]
```bash
curl http://localhost:8000/health
```

**Narrator:**
"Next, we connect Claude Desktop to ComplianceStack."

[Screen: Claude Desktop configuration]

**Narrator:**
"Now we can ask Claude to run a full audit on our model."

[Screen: Claude conversation]
```
"Run a full audit on model 'my-model-v1'. 
Classify it as a general-purpose AI used in employment 
with profiling capabilities, no kill-switch, 
sensitive features: ['race', 'gender', 'age'], 
data controller: 'Acme Corp', DPO: 'Jane Doe'."
```

**Narrator:**
"Claude invokes ComplianceStack's 17 audit tools and returns a comprehensive compliance report."

[Screen: Audit results]

### Key Features (3:30 - 4:00)
[Screen: Feature highlights]

**Narrator:**
"ComplianceStack covers 5 regulatory frameworks:
- EU AI Act
- GDPR
- NIST AI RMF
- ISO 42001
- India DPDP Act

It issues W3C Verifiable Credentials for cryptographically signed audit certificates, and includes a BLOCKER FAIL mechanism that prevents certification of non-compliant models."

### Call to Action (4:00 - 4:30)
[Screen: GitHub repository]

**Narrator:**
"ComplianceStack is open-source under the Apache 2.0 license.

Star the repository on GitHub, try it out, and let us know what you think.

GitHub: github.com/nyayoshbharuchanb15-max/ComplianceStack"

### Closing (4:30 - 5:00)
[Screen: ComplianceStack logo and tagline]

**Narrator:**
"AI governance shouldn't be an afterthought. ComplianceStack makes AI compliance fast, private, and auditable.

Thanks for watching!"

## Video Assets Needed

1. **Screen recording software** (OBS, Camtasia, or similar)
2. **Terminal recording** (asciinema or similar)
3. **Claude Desktop recording**
4. **Logo and graphics** (Canva or similar)
5. **Background music** (royalty-free)
6. **Voiceover** (professional or AI-generated)

## Distribution Plan

### Platforms
- YouTube (main)
- Vimeo (backup)
- Twitter/X (short clip)
- LinkedIn (professional audience)
- Reddit (community)
- Hacker News (technical audience)

### Optimization
- **Title:** "ComplianceStack: AI Compliance Auditing in 5 Minutes"
- **Description:** SEO-optimized with keywords
- **Tags:** AI governance, EU AI Act, GDPR, compliance, MCP, open source
- **Thumbnail:** Eye-catching with logo and tagline
