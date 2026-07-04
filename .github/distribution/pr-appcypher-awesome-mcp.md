# PR: appcypher/awesome-mcp-servers

## Category

Add under: `### Compliance & Governance` or `### Legal & Regulatory`

## PR Title

`feat: add ComplianceStack — EU AI Act / GDPR compliance audit MCP server`

## PR Body

```markdown
### What this adds

[ComplianceStack](https://github.com/nyayoshbharuchanb15-max/ComplianceStack) — an open-source MCP server that runs a 17-phase compliance audit pipeline against AI models, checking adherence to 5 regulatory frameworks:

- **EU AI Act** (Reg. 2024/1689) — Risk classification, human oversight, bias, adversarial robustness
- **GDPR** (Reg. 2016/679) — DPIA, ROPA, DSAR, cross-border transfers
- **NIST AI RMF** (AI 100-1) — Risk mapping, governance, measurement, drift monitoring
- **ISO/IEC 42001:2023** — AIMS compliance, documented information
- **India DPDP Act 2023** — Consent, fiduciary duties, data principal rights

### Key features

- **17 MCP tools** — Risk classification, bias assessment, DPIA generation, adversarial testing, drift detection, agent trust, and more
- **Zero data egress** — All audits run on-premise by default
- **3 transport modes** — stdio, SSE, Streamable HTTP
- **W3C Verifiable Credentials** — Cryptographically signed audit certificates
- **BLOCKER FAIL** — Prevents certification of non-compliant models

### Install

```bash
npx compliance-stack-mcp-server
```

### Links

- [GitHub](https://github.com/nyayoshbharuchanb15-max/ComplianceStack)
- [npm](https://www.npmjs.com/package/compliance-stack-mcp-server)
```

## Checklist

- [ ] Fork the repo
- [ ] Check their README for submission format
- [ ] Add entry under relevant category
- [ ] Open PR with descriptive title
