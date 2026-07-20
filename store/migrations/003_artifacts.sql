-- Evidence artifacts + per-phase article-level citations.
-- Answers: "which specific document proved (or failed to prove) compliance?"
-- Idempotent.

CREATE TABLE IF NOT EXISTS governance_artifacts (
    artifact_id     VARCHAR(100) PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES governance_runs(run_id) ON DELETE CASCADE,
    name            VARCHAR(500) NOT NULL,
    artifact_type   VARCHAR(100) NOT NULL,
    mime_type       VARCHAR(150),
    uri             TEXT,
    content_snippet TEXT,
    sha256          VARCHAR(64)  NOT NULL,
    size_bytes      INTEGER,
    tags            JSONB NOT NULL DEFAULT '[]'::jsonb,
    submitted_by    VARCHAR(255) NOT NULL DEFAULT 'unknown',
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gov_artifacts_run  ON governance_artifacts (run_id);
CREATE INDEX IF NOT EXISTS idx_gov_artifacts_type ON governance_artifacts (artifact_type);

CREATE TABLE IF NOT EXISTS governance_phase_citations (
    id              BIGSERIAL PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES governance_runs(run_id) ON DELETE CASCADE,
    phase_key       VARCHAR(50)  NOT NULL,
    artifact_id     VARCHAR(100),          -- NULL when the citation records a MISSING artifact
    expected_type   VARCHAR(100) NOT NULL,
    framework       VARCHAR(100) NOT NULL,
    article         VARCHAR(100) NOT NULL,
    control         VARCHAR(300) NOT NULL,
    verdict         VARCHAR(50)  NOT NULL,   -- present | pass | warning | fail | missing
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gov_citations_run_phase ON governance_phase_citations (run_id, phase_key);
CREATE INDEX IF NOT EXISTS idx_gov_citations_artifact  ON governance_phase_citations (artifact_id);
