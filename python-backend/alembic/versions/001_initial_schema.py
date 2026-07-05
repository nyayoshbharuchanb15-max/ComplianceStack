# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Initial schema — audit_evidence, certificates, drift_alerts, users, auth_codes, pii_redactions

Revision ID: 001
Revises: None
Create Date: 2026-07-01
"""

from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
    op.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")

    op.create_table(
        "audit_evidence",
        sa.Column("evidence_id", sa.UUID, primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("model_id", sa.String(255), nullable=False),
        sa.Column("audit_phase", sa.String(100), nullable=False),
        sa.Column("evidence_type", sa.String(100), nullable=False, server_default="audit_result"),
        sa.Column("payload", sa.dialects.postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
    )
    op.create_index("idx_evidence_model_id", "audit_evidence", ["model_id"])
    op.create_index("idx_evidence_phase", "audit_evidence", ["audit_phase"])
    op.create_index("idx_evidence_created", "audit_evidence", [sa.text("created_at DESC")])
    op.create_index("idx_evidence_payload_gin", "audit_evidence", [sa.text("payload")], postgresql_using="gin")

    op.create_table(
        "certificates",
        sa.Column("certificate_id", sa.UUID, primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("model_id", sa.String(255), nullable=False),
        sa.Column("vc_payload", sa.dialects.postgresql.JSONB, nullable=False),
        sa.Column("evidence_id", sa.UUID, sa.ForeignKey("audit_evidence.evidence_id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text, nullable=True),
    )
    op.create_index("idx_cert_model", "certificates", ["model_id"])
    op.create_index("idx_cert_expires", "certificates", ["expires_at"])

    op.create_table(
        "drift_alerts",
        sa.Column("alert_id", sa.UUID, primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("model_id", sa.String(255), nullable=False),
        sa.Column("metric", sa.String(255), nullable=False),
        sa.Column("drift_score", sa.Float, nullable=False),
        sa.Column("threshold", sa.Float, nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("acknowledged", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reaudit_triggered", sa.Boolean, nullable=False, server_default="false"),
    )
    op.create_index("idx_drift_model", "drift_alerts", ["model_id"])
    op.create_index("idx_drift_created", "drift_alerts", [sa.text("created_at DESC")])
    op.create_index("idx_drift_status", "drift_alerts", ["status"])

    op.create_table(
        "users",
        sa.Column("user_id", sa.UUID, primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("username", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="viewer"),
        sa.Column("scopes", sa.ARRAY(sa.Text), nullable=False, server_default='{"audit:read"}'),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_users_username", "users", ["username"])

    op.create_table(
        "auth_codes",
        sa.Column("code_id", sa.UUID, primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("code", sa.String(255), unique=True, nullable=False),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column("code_challenge", sa.String(255), nullable=False),
        sa.Column("code_challenge_method", sa.String(10), nullable=False, server_default="S256"),
        sa.Column("redirect_uri", sa.String(1024), nullable=False),
        sa.Column("scope", sa.String(255), nullable=False, server_default="audit:read"),
        sa.Column("auth_user", sa.String(255), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_auth_codes_code", "auth_codes", ["code"])
    op.create_index("idx_auth_codes_expires", "auth_codes", ["expires_at"])

    op.create_table(
        "pii_redactions",
        sa.Column("event_id", sa.UUID, primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("model_id", sa.String(255), nullable=True),
        sa.Column("endpoint", sa.String(255), nullable=False),
        sa.Column("redacted_fields", sa.ARRAY(sa.Text), nullable=False),
        sa.Column("redaction_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("request_path", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_pii_redactions_endpoint", "pii_redactions", ["endpoint"])
    op.create_index("idx_pii_redactions_created", "pii_redactions", [sa.text("created_at DESC")])

    op.execute("""
        CREATE OR REPLACE FUNCTION archive_expired_evidence()
        RETURNS void AS $$
        BEGIN
            UPDATE audit_evidence
            SET payload = jsonb_build_object('archived', true, 'original_type', evidence_type)
            WHERE retention_until IS NOT NULL
              AND retention_until < NOW();
        END;
        $$ LANGUAGE plpgsql
    """)

    op.execute("""
        CREATE OR REPLACE FUNCTION set_default_retention()
        RETURNS TRIGGER AS $$
        BEGIN
            IF NEW.retention_until IS NULL THEN
                NEW.retention_until := NOW() + INTERVAL '7 years';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    """)

    op.execute("""
        CREATE TRIGGER trg_set_retention
            BEFORE INSERT ON audit_evidence
            FOR EACH ROW
            EXECUTE FUNCTION set_default_retention()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_set_retention ON audit_evidence")
    op.drop_table("pii_redactions")
    op.drop_table("auth_codes")
    op.drop_table("users")
    op.drop_table("drift_alerts")
    op.drop_table("certificates")
    op.drop_table("audit_evidence")
