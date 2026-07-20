-- Rich artifact ingest — server-side sha256, extracted text, and per-artifact
-- structural gap findings. Answers "the DPIA was uploaded, but Art. 35(7)(a)
-- 'measures envisaged' is not present in the document text."
-- Idempotent.

ALTER TABLE governance_artifacts
    ADD COLUMN IF NOT EXISTS storage_path      TEXT,
    ADD COLUMN IF NOT EXISTS extracted_text    TEXT,
    ADD COLUMN IF NOT EXISTS extracted_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS extraction_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS extraction_note   TEXT,
    ADD COLUMN IF NOT EXISTS gap_findings      JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS gap_score         NUMERIC(5,4);

CREATE INDEX IF NOT EXISTS idx_gov_artifacts_ext_status
    ON governance_artifacts (extraction_status);

-- Per-phase gap findings (rolled up from the artifacts cited in that phase).
CREATE TABLE IF NOT EXISTS governance_phase_gaps (
    id              BIGSERIAL PRIMARY KEY,
    run_id          UUID         NOT NULL REFERENCES governance_runs(run_id) ON DELETE CASCADE,
    phase_key       VARCHAR(50)  NOT NULL,
    artifact_id     VARCHAR(100) NOT NULL,
    framework       VARCHAR(100) NOT NULL,
    article         VARCHAR(100) NOT NULL,
    section         VARCHAR(300) NOT NULL,
    verdict         VARCHAR(50)  NOT NULL,      -- present | partial | gap
    severity        VARCHAR(20)  NOT NULL DEFAULT 'info',  -- info | warning | blocker
    evidence_span   TEXT,                       -- excerpt from the document
    note            TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gov_phase_gaps_run_phase ON governance_phase_gaps (run_id, phase_key);
CREATE INDEX IF NOT EXISTS idx_gov_phase_gaps_artifact  ON governance_phase_gaps (artifact_id);
