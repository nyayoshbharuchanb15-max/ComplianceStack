# SPDX-License-Identifier: Apache-2.0
"""Dedicated certificate signing service (internal-only, holds the Ed25519 key)."""
from __future__ import annotations
from fastapi import FastAPI
from pydantic import BaseModel

from certs.signer import get_signer, verify_with_method

app = FastAPI(title="Governance Certificate Signer", version="1.0.0")


class SignRequest(BaseModel):
    document: dict


class VerifyRequest(BaseModel):
    credential: dict


@app.get("/health")
async def health():
    signer = get_signer()
    return {"status": "ok", "did": signer.did}


@app.get("/public-key")
async def public_key():
    signer = get_signer()
    return {"did": signer.did, "publicKeyMultibase": signer.public_key_multibase,
            "verificationMethod": signer.verification_method}


@app.post("/sign")
async def sign(req: SignRequest):
    signer = get_signer()
    return {"proof": signer.create_proof(req.document),
            "verificationMethod": signer.verification_method}


@app.post("/verify")
async def verify(req: VerifyRequest):
    method = (req.credential.get("proof") or {}).get("verificationMethod", "")
    signer = get_signer()
    # Signer service verifies only credentials it issued (self-DID).
    return {"verified": verify_with_method(req.credential, method,
                                           trusted_dids=[signer.did])}
