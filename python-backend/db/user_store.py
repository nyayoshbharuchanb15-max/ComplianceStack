# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
PostgreSQL-Backed User Store for OAuth 2.1 Authentication
──────────────────────────────────────────────────────────
Replaces the hardcoded USERS dict with a proper database-backed
user store using bcrypt password hashing (passlib).

OWASP ASVS v4.0.3 — Password storage:
  - Arc 2.1: Passwords are hashed with bcrypt, never stored in plain text
  - Arc 2.4: Password hashes use a work factor of 12

GDPR Art. 5(1)(f) — Integrity and confidentiality: passwords are
hashed with bcrypt, not stored in plain text.
"""

from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import asyncpg
from passlib.hash import bcrypt

from services.auth import Role, Scope, ROLE_SCOPES

logger = logging.getLogger("user_store")


class UserStore:
    """Async PostgreSQL user store with bcrypt password hashing."""

    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self, pool: asyncpg.Pool) -> None:
        """Bind to an existing asyncpg connection pool."""
        self.pool = pool
        await self._ensure_table()
        await self._seed_default_users()

    async def _ensure_table(self) -> None:
        """Create the users table if it does not exist."""
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot ensure users table")
            return
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        user_id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        username        VARCHAR(255) UNIQUE NOT NULL,
                        password_hash   TEXT NOT NULL,
                        role            VARCHAR(50) NOT NULL DEFAULT 'viewer',
                        scopes          TEXT[] NOT NULL DEFAULT '{"audit:read"}',
                        is_active       BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
        except Exception:
            logger.exception("Failed to ensure users table")

    async def _seed_default_users(self) -> None:
        """Seed default dev users only when the table is empty."""
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot seed users")
            return
        try:
            async with self.pool.acquire() as conn:
                count = await conn.fetchval("SELECT COUNT(*) FROM users")
                if count == 0:
                    defaults = [
                        ("admin",   "admin123",   Role.admin,   [s.value for s in ROLE_SCOPES[Role.admin]]),
                        ("auditor", "auditor123", Role.auditor, [s.value for s in ROLE_SCOPES[Role.auditor]]),
                        ("viewer",  "viewer123",  Role.viewer,  [s.value for s in ROLE_SCOPES[Role.viewer]]),
                    ]
                    for username, password, role, scopes in defaults:
                        pw_hash = bcrypt.hash(password)
                        await conn.execute(
                            """INSERT INTO users (username, password_hash, role, scopes)
                               VALUES ($1, $2, $3, $4::text[])
                               ON CONFLICT (username) DO NOTHING""",
                            username, pw_hash, role.value, scopes,
                        )
        except Exception:
            logger.exception("Failed to seed default users")

    async def authenticate(self, username: str, password: str) -> Optional[dict[str, Any]]:
        """
        Verify username and password against the database.

        Returns the user dict (without password_hash) on success,
        or None if credentials are invalid or the user is inactive.
        """
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot authenticate")
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM users WHERE username = $1 AND is_active = TRUE",
                    username,
                )
                if row is None:
                    return None
                if bcrypt.verify(password, row["password_hash"]):
                    return dict(row)
                return None
        except Exception:
            logger.exception("Authentication query failed")
            return None

    async def get_user(self, username: str) -> Optional[dict[str, Any]]:
        """Retrieve a user by username (password_hash excluded)."""
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot get user")
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """SELECT user_id, username, role, scopes, is_active, created_at
                       FROM users WHERE username = $1""",
                    username,
                )
                return dict(row) if row else None
        except Exception:
            logger.exception("Failed to get user")
            return None

    async def create_user(
        self,
        username: str,
        password: str,
        role: Role,
        scopes: Optional[list[str]] = None,
    ) -> Optional[dict[str, Any]]:
        """Create a new user with a bcrypt-hashed password."""
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot create user")
            return None
        pw_hash = bcrypt.hash(password)
        resolved_scopes = scopes or [s.value for s in ROLE_SCOPES.get(role, [Scope.audit_read])]
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """INSERT INTO users (username, password_hash, role, scopes)
                       VALUES ($1, $2, $3, $4::text[])
                       RETURNING user_id, username, role, scopes, is_active, created_at""",
                    username, pw_hash, role.value, resolved_scopes,
                )
                return dict(row) if row else None
        except Exception:
            logger.exception("Failed to create user")
            return None

    async def update_password(self, username: str, new_password: str) -> bool:
        """Update a user's password. Returns True on success."""
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot update password")
            return False
        pw_hash = bcrypt.hash(new_password)
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    """UPDATE users SET password_hash = $1, updated_at = $2
                       WHERE username = $3""",
                    pw_hash, datetime.now(timezone.utc).isoformat(), username,
                )
                return result != "UPDATE 0"
        except Exception:
            logger.exception("Failed to update password")
            return False

    async def list_users(self) -> list[dict[str, Any]]:
        """List all users (password hashes excluded)."""
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot list users")
            return []
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    """SELECT user_id, username, role, scopes, is_active, created_at
                       FROM users ORDER BY created_at DESC""",
                )
                return [dict(r) for r in rows]
        except Exception:
            logger.exception("Failed to list users")
            return []

    async def store_auth_code(
        self,
        code: str,
        client_id: str,
        code_challenge: str,
        code_challenge_method: str,
        redirect_uri: str,
        scope: str,
        auth_user: str,
    ) -> None:
        """Persist an OAuth 2.1 authorization code with PKCE challenge."""
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot store auth code")
            return
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO auth_codes
                       (code, client_id, code_challenge, code_challenge_method,
                        redirect_uri, scope, auth_user, expires_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7,
                               NOW() + INTERVAL '10 minutes')""",
                    code, client_id, code_challenge, code_challenge_method,
                    redirect_uri, scope, auth_user,
                )
        except Exception:
            logger.exception("Failed to store auth code")

    async def consume_auth_code(self, code: str) -> Optional[dict[str, Any]]:
        """
        Consume (mark used and return) an authorization code.

        Returns the code record if valid and unused, or None.
        """
        if self.pool is None:
            logger.warning("PostgreSQL pool not available — cannot consume auth code")
            return None
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """UPDATE auth_codes SET used = TRUE
                       WHERE code = $1 AND used = FALSE AND expires_at > NOW()
                       RETURNING *""",
                    code,
                )
                return dict(row) if row else None
        except Exception:
            logger.exception("Failed to consume auth code")
            return None


user_store = UserStore()
