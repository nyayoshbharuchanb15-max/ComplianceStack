-- ═══════════════════════════════════════════════════════════════════
--  AI Governance Evidence Store — PostgreSQL Schema
--  ISO/IEC 42001:2023 Clause 7.5 — Documented Information
--  ═══════════════════════════════════════════════════════════════════
--
--  This schema provides:
--    1. audit_evidence:  Flexible JSONB store for all audit artifacts
--    2. certificates:    W3C Verifiable Credentials (VC-JSON)
--    3. drift_alerts:    Time-series drift monitoring events
--
--  Regulatory mappings:
--    • EU AI Act Art. 12 — Technical Documentation
--    • GDPR Art. 5(1)(e) — Storage Limitation
--    • GDPR Art. 30 — Records of Processing Activities
--    • ISO/IEC 42001:2023 Clause 7.5 — Documented Information
--
--  All tables include immutable created_at timestamps for audit
--  trail integrity. The 'payload' JSONB columns are schema-flexible
--  to accommodate evolving regulatory requirements.

-- ─── Extensions ──────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Audit Evidence Store ───────────────────────────────────────
--  ISO 42001 Clause 7.5.1: Documented information shall be retained.
--  GDPR Art. 30: Records of processing activities shall be maintained.

CREATE TABLE IF NOT EXISTS audit_evidence (
    evidence_id     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id        VARCHAR(255) NOT NULL,
    audit_phase     VARCHAR(100) NOT NULL,
    -- Auditable phases: risk_classification, supply_chain, human_oversight,
    --                   bias_assessment, dpia, adversarial_testing,
    --                   scoring, certificate_generation, drift_monitoring
    evidence_type   VARCHAR(100) NOT NULL DEFAULT 'audit_result',
    -- JSONB payload — schema-flexible for varying audit artifacts.
    -- Each payload contains:
    --   - The full audit result object
    --   - mappedArticles (list of regulatory references)
    --   - iso42001Clause reference
    --   - compliant boolean
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- GDPR Art. 5(1)(e): Storage limitation enforced via retention policy
    retention_until TIMESTAMPTZ,
    -- ISO 42001 Clause 7.5.2: Versioning for document control
    version         INTEGER NOT NULL DEFAULT 1
);

-- Indexes for fast retrieval
CREATE INDEX IF NOT EXISTS idx_evidence_model_id ON audit_evidence (model_id);
CREATE INDEX IF NOT EXISTS idx_evidence_phase ON audit_evidence (audit_phase);
CREATE INDEX IF NOT EXISTS idx_evidence_created ON audit_evidence (created_at DESC);
-- GIN index for JSONB queries (e.g., querying specific compliance flags)
CREATE INDEX IF NOT EXISTS idx_evidence_payload_gin ON audit_evidence USING GIN (payload);

COMMENT ON TABLE audit_evidence IS
  'Audit evidence store — ISO 42001:2023 Clause 7.5 documented information. '
  'Stores all 9-phase audit artifacts as JSONB for schema flexibility.';
COMMENT ON COLUMN audit_evidence.payload IS
  'JSONB audit result with regulatory mappings (mappedArticles, iso42001Clause).';
COMMENT ON COLUMN audit_evidence.retention_until IS
  'GDPR Art. 5(1)(e) storage limitation — evidence auto-expiry date.';

-- ─── W3C Verifiable Credentials ──────────────────────────────────
--  ISO 42001 Clause 7.5: Certificates are documented information.
--  W3C VC Data Model 1.1: Standard for verifiable credentials.

CREATE TABLE IF NOT EXISTS certificates (
    certificate_id  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id        VARCHAR(255) NOT NULL,
    vc_payload      JSONB NOT NULL,
    -- W3C VC-JSON structure with @context, type, issuer, proof
    evidence_id     UUID REFERENCES audit_evidence(evidence_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_cert_model ON certificates (model_id);
CREATE INDEX IF NOT EXISTS idx_cert_expires ON certificates (expires_at);

COMMENT ON TABLE certificates IS
  'W3C Verifiable Credentials — Ed25519-signed audit certificates. '
  'Each VC is self-contained and cryptographically verifiable.';

-- ─── Drift Alerts (Time-Series) ──────────────────────────────────
--  EU AI Act Art. 15: Ongoing monitoring for accuracy and robustness.
--  ISO 42001 Clause 9.1: Performance monitoring and corrective action.

CREATE TABLE IF NOT EXISTS drift_alerts (
    alert_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id        VARCHAR(255) NOT NULL,
    metric          VARCHAR(255) NOT NULL,
    drift_score     DOUBLE PRECISION NOT NULL,
    threshold       DOUBLE PRECISION NOT NULL,
    status          VARCHAR(50) NOT NULL,  -- 'stable', 'warning', 'critical'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    reaudit_triggered BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_drift_model ON drift_alerts (model_id);
CREATE INDEX IF NOT EXISTS idx_drift_created ON drift_alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_drift_status ON drift_alerts (status);

COMMENT ON TABLE drift_alerts IS
  'Model drift monitoring events — EU AI Act Art. 15 continuous monitoring. '
  'Critical drift triggers automated re-audit via Redis Streams.';

-- ─── Users Table ─────────────────────────────────────────────────
--  PostgreSQL-backed user store for OAuth 2.1 authentication.
--  Replaces the hardcoded USERS dict with proper password hashing.
--
--  OWASP ASVS v4.0.3 — Passwords are stored as bcrypt hashes.
--  GDPR Art. 5(1)(f) — Integrity and confidentiality of personal data.

CREATE TABLE IF NOT EXISTS users (
    user_id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        VARCHAR(255) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            VARCHAR(50) NOT NULL DEFAULT 'viewer',
    scopes          TEXT[] NOT NULL DEFAULT '{"audit:read"}',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

COMMENT ON TABLE users IS
  'OAuth 2.1 user store — bcrypt-hashed passwords with RBAC roles and scopes.';

-- ─── OAuth 2.1 Authorization Codes Table ──────────────────────────
--  PKCE + state validation for authorization code flow.
--  Codes are single-use with short TTL enforced by the application.

CREATE TABLE IF NOT EXISTS auth_codes (
    code_id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code                VARCHAR(255) UNIQUE NOT NULL,
    client_id           VARCHAR(255) NOT NULL,
    code_challenge      VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    redirect_uri        VARCHAR(1024) NOT NULL,
    scope               VARCHAR(255) NOT NULL DEFAULT 'audit:read',
    auth_user           VARCHAR(255) NOT NULL,
    used                BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON auth_codes (code);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes (expires_at);

COMMENT ON TABLE auth_codes IS
  'OAuth 2.1 authorization codes with PKCE challenge — single-use, short TTL.';

-- ─── PII Redaction Events ─────────────────────────────────────────
--  GDPR Art. 5(1)(c): Data minimisation — log what was redacted, not the PII itself.
--  GDPR Art. 5(2): Accountability — data controller must demonstrate compliance.

CREATE TABLE IF NOT EXISTS pii_redactions (
    event_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id        VARCHAR(255),
    endpoint        VARCHAR(255) NOT NULL,
    redacted_fields TEXT[] NOT NULL,
    redaction_count INTEGER NOT NULL DEFAULT 0,
    request_path    VARCHAR(1024),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pii_redactions_endpoint ON pii_redactions (endpoint);
CREATE INDEX IF NOT EXISTS idx_pii_redactions_created ON pii_redactions (created_at DESC);

COMMENT ON TABLE pii_redactions IS
  'PII redaction audit log — field names only, no PII values. '
  'GDPR Art. 5(1)(c) data minimisation compliance evidence.';

-- ─── Audit Trail (Mutation Log) ───────────────────────────────────
--  GDPR Art. 5(2) — Accountability: controller must demonstrate compliance.
--  ISO 42001:2023 Clause 7.5 — Documented information includes mutation history.
--  EU AI Act Art. 12 — Technical documentation must include audit events.

CREATE TABLE IF NOT EXISTS audit_trail (
    event_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id        VARCHAR(255) NOT NULL,
    phase           VARCHAR(100) NOT NULL,
    action          VARCHAR(100) NOT NULL,
    -- e.g., 'risk_classified', 'certificate_generated', 'evidence_stored'
    actor           VARCHAR(255) NOT NULL DEFAULT 'system',
    -- Who performed the action: 'system', 'user:<id>', 'mcp:<id>'
    outcome         VARCHAR(50) NOT NULL DEFAULT 'success',
    -- 'success', 'failure', 'partial'
    details         JSONB,
    -- Additional context: error messages, input summary, etc.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_trail_model ON audit_trail (model_id);
CREATE INDEX IF NOT EXISTS idx_audit_trail_phase ON audit_trail (phase);
CREATE INDEX IF NOT EXISTS idx_audit_trail_created ON audit_trail (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_action ON audit_trail (action);

COMMENT ON TABLE audit_trail IS
  'Audit trail mutation log — GDPR Art. 5(2) accountability. '
  'Records every audit phase execution with actor, outcome, and timestamp.';
COMMENT ON COLUMN audit_trail.action IS
  'Action performed: risk_classified, supply_chain_audited, certificate_generated, etc.';

-- ─── Retention Policy Function ───────────────────────────────────
--  GDPR Art. 5(1)(e): Enforce storage limitation.

CREATE OR REPLACE FUNCTION archive_expired_evidence()
RETURNS void AS $$
BEGIN
    UPDATE audit_evidence
    SET payload = jsonb_build_object('archived', true, 'original_type', evidence_type)
    WHERE retention_until IS NOT NULL
      AND retention_until < NOW();
END;
$$ LANGUAGE plpgsql;

-- ─── Trigger: Auto-set retention for evidence ────────────────────
--  Default retention: 7 years (per GDPR Art. 5(1)(e) common practice)

CREATE OR REPLACE FUNCTION set_default_retention()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.retention_until IS NULL THEN
        NEW.retention_until := NOW() + INTERVAL '7 years';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_retention
    BEFORE INSERT ON audit_evidence
    FOR EACH ROW
    EXECUTE FUNCTION set_default_retention();

-- ─── Seed Data: Compliance Framework References ─────────────────

INSERT INTO audit_evidence (evidence_id, model_id, audit_phase, evidence_type, payload)
VALUES
    (
        '00000000-0000-0000-0000-000000000001',
        '__schema_init__',
        'schema_initialization',
        'system_metadata',
        jsonb_build_object(
            'schema_version', '1.0.0',
            'framework', 'AI Governance MCP Server',
            'init_timestamp', NOW(),
            'supported_regulations', jsonb_build_array(
                'EU AI Act (Regulation 2024/1689)',
                'NIST AI RMF (NIST AI 100-1)',
                'ISO/IEC 42001:2023',
                'GDPR (Regulation 2016/679)'
            )
        )
    )
ON CONFLICT (evidence_id) DO NOTHING;
