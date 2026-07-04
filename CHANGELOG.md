# Changelog

All notable changes to ComplianceStack will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-07-04

### Added

- **npm Distribution**: `bin` field for npx support, `files` whitelist, `engines` constraint, `.npmignore`
- **Community Outreach**: PR drafts for 5 awesome-MCP lists + legal tech lists
- **MCP Registry**: Publishing guide with `mcp-publisher` CLI instructions
- **Social Content**: Post drafts for r/mcp, r/ClaudeAI, r/artificial, and Hacker News
- **package-lock.json**: Committed for reproducible npm workspaces installs

### Changed

- **README**: Consolidated duplicate Quick Start sections, reordered Features (Architecture → Pipeline → Regulatory), collapsed validation into `<details>`
- **README**: Fixed nav link anchors, added npx quick-install at top for immediate onboarding
- **.gitignore**: Added `.idea/` and `.vscode/`

## [3.0.0] - 2026-07-04

### Fixed

- **MCP Server Transport**: Fixed `StreamableHTTPTransport.start()` RangeError — snapshot `_pendingMessages` before iterating
- **Session Cleanup**: Changed hardcoded 60s interval to `Math.min(this._sessionTimeout, 60000)`
- **Error Formatting**: Removed `[MCP Error X]` prefix from `mcpError()` helper
- **TypeScript Errors**: 11 typecheck fixes (ajv import, CancelledNotification handler, SDK JSONRPCMessage imports, etc.)
- **Backend Bias Engine**: Replaced unavailable fairlearn metrics (`equal_opportunity_difference`, `disparate_impact_ratio`) with custom implementations using `MetricFrame` + sklearn
- **Pydantic v2 ForwardRef**: Removed `from __future__ import annotations` from 12 routers to fix `PydanticUndefinedAnnotation`
- **bcrypt Compatibility**: Pinned `bcrypt==4.0.1` for passlib 1.7.4 compatibility
- **require_scope**: Fixed decorator to prefer `request_obj` (Starlette Request) over body model
- **Adversarial Boundaries**: Changed `>` to `>=` in `_severity_from_rate`; `<` to `<=` in `_to_test_result`
- **VC Proof**: Added `VCProof` to `VCIssuer.issue()` constructor
- **Test Mocks**: Added async mocks for `_is_jti_blacklisted`, PKCE `consume_auth_code`, LLM `_chat_completion`/`_judge_response`

### Changed

- **Test Suite**: 244/244 tests green (up from 178 passed, 15 failed, 29 errors)
- **MCP Server**: 32/32 tests green, typecheck 0 errors, build compiles clean
- **Adversarial Tests**: Mocked HTTP calls instead of connecting to nonexistent LLM endpoint

## [2.0.0] - 2026-07-02

### Added

- **17-Phase Audit Pipeline**: Complete AI compliance auditing across 5 regulatory frameworks
- **MCP Server**: TypeScript implementation with Model Context Protocol SDK
- **Python Backend**: FastAPI services for all audit logic
- **W3C Verifiable Credentials**: Cryptographically signed audit certificates
- **BLOCKER FAIL Mechanism**: Prevents certification of non-compliant models
- **Zero Data Egress Architecture**: All operations in-process, no external API calls
- **OAuth 2.1 + RBAC**: Role-based access control with scoped endpoints
- **Merkle Audit Trail**: Tamper-evident evidence chain
- **PII Redaction Middleware**: Intercepts and redacts PII from API responses
- **Docker Orchestration**: Complete containerized deployment
- **CI/CD Pipeline**: GitHub Actions for testing and deployment

### Regulatory Coverage

- **EU AI Act** (Reg. 2024/1689): Art. 5, 6, 10, 12, 14, 15, Annex I–III
- **NIST AI RMF** (AI 100-1): MAP 1.1, GOVERN 1.2, 3.2, MEASURE 1.3, 2.2, 3.3, 4.1
- **ISO/IEC 42001:2023**: Clauses 6.1, 6.2, 7.4.3, 7.5, 8.1.2, 8.1.3, 8.2, 9.1
- **GDPR** (Reg. 2016/679): Art. 5, 9, 22, 25, 30, 35, 44–49
- **India DPDP Act 2023**: Sec. 5–14

### MCP Tools

1. `classify_ai_risk` - EU AI Act risk tier classification
2. `discover_supply_chain` - Filesystem crawler with Neo4j provenance graph
3. `audit_supply_chain` - Supply chain audit via Neo4j graph queries
4. `verify_human_oversight` - HITL/kill-switch verification
5. `run_bias_assessment` - Fairlearn bias metrics
6. `generate_dpia` - GDPR Art. 35 DPIA generation
7. `run_adversarial_tests` - Prompt injection, jailbreak, OOD testing
8. `score_audit_weighted` - Aggregate scoring with BLOCKER FAIL
9. `generate_audit_certificate` - W3C Verifiable Credential issuance
10. `monitor_model_drift` - Evidently AI drift detection
11. `audit_session_memory` - STM/LTM isolation audit
12. `audit_rag_quality` - RAG pipeline quality evaluation
13. `audit_prompt_templates` - Injection surface assessment
14. `audit_agent_trust` - Multi-agent trust verification
15. `audit_tool_permissions` - Privilege escalation detection
16. `classify_agent_autonomy` - Agent autonomy classification
17. `assess_dpdp_compliance` - India DPDP Act compliance

### Security

- Ed25519 cryptographic signing for audit certificates
- Zero-trust architecture with OAuth 2.1
- On-premise deployment with no external dependencies
- Merkle audit trail for tamper-evident evidence

## [1.0.0] - 2026-06-15

### Added

- Initial release with core audit pipeline
- Basic EU AI Act compliance checking
- Docker deployment support
