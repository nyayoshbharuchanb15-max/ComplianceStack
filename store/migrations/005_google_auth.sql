-- Google Auth sessions — persisted so /auth/me survives worker restarts.
-- Idempotent.

CREATE TABLE IF NOT EXISTS governance_google_sessions (
    session_token   TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    email           TEXT NOT NULL,
    name            TEXT,
    picture         TEXT,
    role            TEXT NOT NULL DEFAULT 'governance-admin',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_google_sessions_email ON governance_google_sessions(email);
CREATE INDEX IF NOT EXISTS idx_google_sessions_expires ON governance_google_sessions(expires_at);
