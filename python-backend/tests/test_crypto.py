# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Cryptographic Signing (W3C VC)
"""

import json
from services.crypto_signer import CryptoSigner, _base58_encode, _multibase_base58btc


class TestBase58Encoding:
    def test_base58_encode_known_value(self):
        result = _base58_encode(bytes.fromhex("00"))
        assert result == "1"

    def test_base58_encode_non_empty(self):
        result = _base58_encode(b"hello")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_multibase_prefix(self):
        result = _multibase_base58btc(b"test")
        assert result.startswith("z")


class TestCryptoSigner:
    def setup_method(self):
        self.signer = CryptoSigner()

    def test_sign_and_verify(self):
        payload = b'{"test": "data"}'
        signature = self.signer.sign_payload(payload)
        assert signature.startswith("z")
        assert self.signer.verify_signature(payload, signature) is True

    def test_verify_wrong_payload_fails(self):
        payload = b'{"test": "data"}'
        signature = self.signer.sign_payload(payload)
        assert self.signer.verify_signature(b'{"wrong": "payload"}', signature) is False

    def test_verification_method_format(self):
        vm = self.signer.verification_method
        assert vm.startswith("did:key:z")
        assert "#" in vm

    def test_sign_vc_payload(self):
        vc = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "urn:uuid:test-123",
            "type": ["VerifiableCredential", "AIAuditCertificate"],
            "issuer": {"id": "did:web:test"},
            "credentialSubject": {"modelId": "test-model"},
            "proof": {"type": "Ed25519Signature2020"},
        }
        sig = self.signer.sign_vc_payload(vc)
        assert sig.startswith("z")
        # Proof field should be restored
        assert "proof" in vc
