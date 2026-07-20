# SPDX-License-Identifier: Apache-2.0
"""Immutable JSONB evidence records — runs, phase results, certificates, events, monitoring."""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from store.db import db


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_dict(row) -> dict:
    d = dict(row)
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.isoformat()
        elif isinstance(v, uuid.UUID):
            d[k] = str(v)
        elif k in ("inputs", "outputs", "legal_mappings", "blocker_reasons",
                   "context", "trigger", "vc_payload", "payload", "config") and isinstance(v, str):
            d[k] = json.loads(v)
    return d


# ─── Runs ────────────────────────────────────────────────────────

async def create_run(model_id: str, model_version: str, context: dict,
                     reaudit_of: Optional[str] = None, trigger: Optional[dict] = None) -> str:
    run_id = str(uuid.uuid4())
    async with db.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO governance_runs (run_id, model_id, model_version, status,
                   reaudit_of, trigger, context, created_at, updated_at)
               VALUES ($1,$2,$3,'in_progress',$4,$5::jsonb,$6::jsonb,$7,$7)""",
            run_id, model_id, model_version, reaudit_of,
            json.dumps(trigger) if trigger else None, json.dumps(context), _now())
    return run_id


async def get_run(run_id: str) -> Optional[dict]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM governance_runs WHERE run_id = $1", run_id)
    return _row_to_dict(row) if row else None


async def update_run_status(run_id: str, status: str) -> None:
    async with db.pool.acquire() as conn:
        await conn.execute(
            "UPDATE governance_runs SET status=$2, updated_at=$3 WHERE run_id=$1",
            run_id, status, _now())


async def update_run_context(run_id: str, context: dict) -> None:
    async with db.pool.acquire() as conn:
        await conn.execute(
            "UPDATE governance_runs SET context=$2::jsonb, updated_at=$3 WHERE run_id=$1",
            run_id, json.dumps(context), _now())


async def latest_certified_run(model_id: str) -> Optional[dict]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT * FROM governance_runs
               WHERE model_id=$1 AND status IN ('certified','monitoring_active')
               ORDER BY created_at DESC LIMIT 1""", model_id)
    return _row_to_dict(row) if row else None


async def list_runs(model_id: Optional[str] = None,
                    status: Optional[str] = None,
                    limit: int = 50) -> list[dict]:
    q = "SELECT * FROM governance_runs"
    args: list = []
    where: list[str] = []
    if model_id:
        args.append(model_id)
        where.append(f"model_id=${len(args)}")
    if status:
        args.append(status)
        where.append(f"status=${len(args)}")
    if where:
        q += " WHERE " + " AND ".join(where)
    q += f" ORDER BY created_at DESC LIMIT {int(limit)}"
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(q, *args)
    out: list[dict] = []
    for r in rows:
        d = _row_to_dict(r)
        out.append({"runId": d["run_id"], "modelId": d["model_id"],
                    "modelVersion": d["model_version"], "status": d["status"],
                    "reauditOf": d.get("reaudit_of"),
                    "createdAt": d["created_at"], "updatedAt": d["updated_at"]})
    return out


async def list_certificates(model_id: Optional[str] = None,
                            status: Optional[str] = None,
                            limit: int = 50) -> list[dict]:
    q = ("SELECT certificate_id, run_id, model_id, status, supersedes, "
         "superseded_by, anchor_hash, issued_at, expires_at, revoked_at, "
         "revocation_reason FROM governance_certificates")
    args: list = []
    where: list[str] = []
    if model_id:
        args.append(model_id)
        where.append(f"model_id=${len(args)}")
    if status:
        args.append(status)
        where.append(f"status=${len(args)}")
    if where:
        q += " WHERE " + " AND ".join(where)
    q += f" ORDER BY issued_at DESC LIMIT {int(limit)}"
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(q, *args)
    out = []
    for r in rows:
        d = _row_to_dict(r)
        out.append({
            "certificateId": d["certificate_id"], "runId": d["run_id"],
            "modelId": d["model_id"], "status": d["status"],
            "supersedes": d.get("supersedes"), "supersededBy": d.get("superseded_by"),
            "anchorHash": d["anchor_hash"], "issuedAt": d["issued_at"],
            "expiresAt": d.get("expires_at"), "revokedAt": d.get("revoked_at"),
            "revocationReason": d.get("revocation_reason"),
        })
    return out


# ─── Phase results ───────────────────────────────────────────────

async def insert_phase_result(run_id: str, phase_key: str, phase_number: int, status: str,
                              inputs: dict, outputs: dict, legal_mappings: list,
                              blocker_reasons: list, control_version: str,
                              integrity_hash_value: str, prev_hash: str,
                              actor: str = "system", carried_forward: bool = False,
                              origin_run_id: Optional[str] = None) -> dict:
    result_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    created_at = _now()
    async with db.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO governance_phase_results
                   (result_id, run_id, phase_key, phase_number, status, inputs, outputs,
                    legal_mappings, blocker_reasons, control_version, integrity_hash,
                    prev_hash, evidence_id, carried_forward, origin_run_id, actor, created_at)
               VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,
                       $10,$11,$12,$13,$14,$15,$16,$17)""",
            result_id, run_id, phase_key, phase_number, status,
            json.dumps(inputs), json.dumps(outputs), json.dumps(legal_mappings),
            json.dumps(blocker_reasons), control_version, integrity_hash_value,
            prev_hash, evidence_id, carried_forward, origin_run_id, actor, created_at)
    return {"result_id": result_id, "evidence_id": evidence_id,
            "created_at": created_at.isoformat()}


async def get_phase_results(run_id: str) -> list[dict]:
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM governance_phase_results WHERE run_id=$1 ORDER BY phase_number",
            run_id)
    return [_row_to_dict(r) for r in rows]


async def get_phase_result(run_id: str, phase_key: str) -> Optional[dict]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM governance_phase_results WHERE run_id=$1 AND phase_key=$2",
            run_id, phase_key)
    return _row_to_dict(row) if row else None


# ─── Certificates ────────────────────────────────────────────────

async def insert_certificate(certificate_id: str, run_id: str, model_id: str,
                             vc_payload: dict, anchor_hash: str, verification_method: str,
                             expires_at: Optional[datetime], supersedes: Optional[str] = None) -> None:
    async with db.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO governance_certificates
                   (certificate_id, run_id, model_id, vc_payload, status, supersedes,
                    anchor_hash, verification_method, issued_at, expires_at)
               VALUES ($1,$2,$3,$4::jsonb,'active',$5,$6,$7,$8,$9)""",
            certificate_id, run_id, model_id, json.dumps(vc_payload), supersedes,
            anchor_hash, verification_method, _now(), expires_at)
        if supersedes:
            await conn.execute(
                """UPDATE governance_certificates SET status='superseded', superseded_by=$2
                   WHERE certificate_id=$1 AND status='active'""",
                supersedes, certificate_id)


async def get_certificate(certificate_id: str) -> Optional[dict]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM governance_certificates WHERE certificate_id=$1", certificate_id)
    return _row_to_dict(row) if row else None


async def get_active_certificate(model_id: str) -> Optional[dict]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT * FROM governance_certificates WHERE model_id=$1 AND status='active'
               ORDER BY issued_at DESC LIMIT 1""", model_id)
    return _row_to_dict(row) if row else None


async def get_certificate_for_run(run_id: str) -> Optional[dict]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM governance_certificates WHERE run_id=$1 ORDER BY issued_at DESC LIMIT 1",
            run_id)
    return _row_to_dict(row) if row else None


async def revoke_certificate(certificate_id: str, reason: str) -> bool:
    async with db.pool.acquire() as conn:
        result = await conn.execute(
            """UPDATE governance_certificates
               SET status='revoked', revoked_at=$2, revocation_reason=$3
               WHERE certificate_id=$1 AND status IN ('active','superseded')""",
            certificate_id, _now(), reason)
    return result.endswith("1")


# ─── Event ledger (internal webhook delivery) ────────────────────

async def record_event(event_id: str, stream: str, event_type: str, payload: dict,
                       status: str = "delivered", attempts: int = 1,
                       run_id: Optional[str] = None, phase_key: Optional[str] = None,
                       last_error: Optional[str] = None) -> None:
    async with db.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO governance_events
                   (event_id, stream, event_type, run_id, phase_key, payload,
                    status, attempts, last_error, created_at)
               VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10)
               ON CONFLICT (event_id) DO UPDATE
                   SET status=EXCLUDED.status, attempts=EXCLUDED.attempts,
                       last_error=EXCLUDED.last_error""",
            event_id, stream, event_type, run_id, phase_key, json.dumps(payload),
            status, attempts, last_error, _now())


async def list_events(status: Optional[str] = None, limit: int = 50) -> list[dict]:
    q = "SELECT * FROM governance_events"
    args: list = []
    if status:
        q += " WHERE status=$1"
        args.append(status)
    q += f" ORDER BY created_at DESC LIMIT {int(limit)}"
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(q, *args)
    return [_row_to_dict(r) for r in rows]


# ─── Monitoring ──────────────────────────────────────────────────

async def insert_monitoring_config(run_id: str, model_id: str, config: dict) -> str:
    config_id = str(uuid.uuid4())
    async with db.pool.acquire() as conn:
        await conn.execute(
            "UPDATE governance_monitoring SET active=FALSE WHERE model_id=$1", model_id)
        await conn.execute(
            """INSERT INTO governance_monitoring (config_id, run_id, model_id, config, active, created_at)
               VALUES ($1,$2,$3,$4::jsonb,TRUE,$5)""",
            config_id, run_id, model_id, json.dumps(config), _now())
    return config_id


async def get_active_monitoring(model_id: str) -> Optional[dict]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT * FROM governance_monitoring WHERE model_id=$1 AND active=TRUE
               ORDER BY created_at DESC LIMIT 1""", model_id)
    return _row_to_dict(row) if row else None
