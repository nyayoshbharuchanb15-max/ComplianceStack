# SPDX-License-Identifier: Apache-2.0
"""VC 2.0 credential assembly + issuance per schemas/w3c_audit_credential.jsonld."""
from __future__ import annotations
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx

from certs.signer import canonical_json, get_signer, verify_with_method

SCHEMA_CONTEXT = os.environ.get(
    "VC_SCHEMA_CONTEXT",
    "https://governance.internal/schemas/w3c_audit_credential.jsonld")
CREDENTIAL_TYPE = "AIComplianceAuditCredential"
REQUIRED_FIELDS = ("@context", "id", "type", "issuer", "validFrom", "validUntil",
                   "credentialSubject", "credentialStatus", "proof")


def build_credential(run: dict, phase_results: list[dict], issuer: dict,
                     validity_days: int, status_base_url: str,
                     previous_credential: Optional[str] = None) -> dict:
    now = datetime.now(timezone.utc)
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    signer = get_signer()
    phase_entries = []
    frameworks: set[str] = set()
    for pr in phase_results:
        articles = [{"framework": m["framework"], "article": m["article"],
                     "title": m.get("title", "")} for m in pr["legal_mappings"]]
        for a in articles:
            frameworks.add(a["framework"])
        phase_entries.append({
            "phase": pr["phase_key"],
            "phaseNumber": pr["phase_number"],
            "status": pr["status"],
            "controlVersion": pr["control_version"],
            "integrityHash": pr["integrity_hash"],
            "evidenceId": pr["evidence_id"],
            "carriedForward": pr.get("carried_forward", False),
            "articles": articles,
        })
    run_integrity_hash = phase_results[-1]["integrity_hash"] if phase_results else ""
    subject = {
        "id": f"urn:governance:model:{run['model_id']}@{run['model_version']}",
        "modelId": run["model_id"],
        "modelVersion": run["model_version"],
        "auditRunId": run["run_id"],
        "riskTier": (run.get("context") or {}).get("riskTier", "unclassified"),
        "frameworks": sorted(frameworks),
        "phaseResults": phase_entries,
        "runIntegrityHash": run_integrity_hash,
    }
    if previous_credential:
        subject["previousCredential"] = previous_credential
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2", SCHEMA_CONTEXT],
        "id": credential_id,
        "type": ["VerifiableCredential", CREDENTIAL_TYPE],
        "issuer": {"id": signer.did, "name": issuer.get("name", "AI Governance Authority")},
        "validFrom": now.isoformat(),
        "validUntil": (now + timedelta(days=validity_days)).isoformat(),
        "credentialSubject": subject,
        "credentialStatus": {
            "id": f"{status_base_url}/api/v1/certificates/{credential_id}/status",
            "type": "GovernanceCredentialStatus2026",
            "statusPurpose": "revocation",
        },
    }


async def sign_credential(credential: dict) -> dict:
    """Attach the DataIntegrityProof — via the cert-signer service or embedded key."""
    signer_url = os.environ.get("CERT_SIGNER_URL", "").strip()
    if signer_url:
        async with httpx.AsyncClient(timeout=15) as client:  # internal-only service
            resp = await client.post(f"{signer_url}/sign", json={"document": credential})
            resp.raise_for_status()
            proof = resp.json()["proof"]
    else:
        proof = get_signer().create_proof(credential)
    return {**credential, "proof": proof}


def anchor_hash(credential: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(credential).encode()).hexdigest()


def validate_schema_shape(credential: dict) -> tuple[bool, list[str]]:
    problems = [f for f in REQUIRED_FIELDS if f not in credential]
    ctx = credential.get("@context", [])
    if "https://www.w3.org/ns/credentials/v2" not in ctx:
        problems.append("@context missing credentials/v2")
    if SCHEMA_CONTEXT not in ctx:
        problems.append("@context missing w3c_audit_credential.jsonld")
    if CREDENTIAL_TYPE not in credential.get("type", []):
        problems.append(f"type missing {CREDENTIAL_TYPE}")
    subject = credential.get("credentialSubject", {})
    for field in ("modelId", "auditRunId", "riskTier", "phaseResults", "runIntegrityHash"):
        if field not in subject:
            problems.append(f"credentialSubject.{field} missing")
    proof = credential.get("proof", {})
    for field, expected in (("type", "DataIntegrityProof"), ("cryptosuite", "eddsa-jcs-2022"),
                            ("proofPurpose", "assertionMethod")):
        if proof.get(field) != expected:
            problems.append(f"proof.{field} != {expected}")
    return (len(problems) == 0, problems)


def verify_credential(credential: dict) -> dict[str, Any]:
    from orchestrator.config import trusted_issuer_dids
    schema_ok, problems = validate_schema_shape(credential)
    signature_ok = verify_with_method(
        credential, (credential.get("proof") or {}).get("verificationMethod", ""),
        trusted_dids=trusted_issuer_dids())
    not_expired = True
    valid_until = credential.get("validUntil")
    if valid_until:
        try:
            not_expired = datetime.fromisoformat(valid_until) > datetime.now(timezone.utc)
        except ValueError:
            not_expired = False
    return {"schemaValid": schema_ok, "schemaProblems": problems,
            "signatureValid": signature_ok, "notExpired": not_expired}
