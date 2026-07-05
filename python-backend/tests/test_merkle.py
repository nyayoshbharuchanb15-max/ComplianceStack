# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Merkle Tree Audit Trail
"""

import pytest
from services.merkle_audit import MerkleTree, AuditChain, hash_evidence, sha256


class TestMerkleTree:
    def test_single_leaf(self):
        tree = MerkleTree(["hash1"])
        assert tree.root == "hash1"

    def test_two_leaves(self):
        tree = MerkleTree(["a", "b"])
        expected = sha256(("a" + "b").encode("utf-8"))
        assert tree.root == expected

    def test_odd_leaves(self):
        tree = MerkleTree(["a", "b", "c"])
        expected = sha256(
            (sha256(("a" + "b").encode("utf-8")) + sha256(("c" + "c").encode("utf-8"))).encode("utf-8")
        )
        assert tree.root == expected

    def test_proof_verification(self):
        leaves = [sha256(str(i).encode()) for i in range(4)]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(1)
        assert MerkleTree.verify_proof(leaves[1], proof, tree.root) is True

    def test_proof_wrong_leaf_fails(self):
        leaves = [sha256(str(i).encode()) for i in range(4)]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(1)
        assert MerkleTree.verify_proof(sha256(b"wrong"), proof, tree.root) is False


class TestAuditChain:
    def test_append_record(self):
        chain = AuditChain()
        h1 = chain.append({"phase": "risk_classification", "result": "pass"})
        h2 = chain.append({"phase": "bias_assessment", "result": "fail"})
        assert len(chain.hashes) == 2
        assert h1 != h2

    def test_merkle_root_changes_on_tamper(self):
        chain = AuditChain()
        chain.append({"phase": "risk", "result": "pass"})
        root1 = chain.merkle_root

        chain.append({"phase": "bias", "result": "fail"})
        root2 = chain.merkle_root

        assert root1 != root2

    def test_hash_links_to_previous(self):
        h1 = hash_evidence({"phase": "first"}, "00" * 32)
        h2 = hash_evidence({"phase": "second"}, h1)
        # If we change h1, h2 verification should fail
        h1_tampered = hash_evidence({"phase": "first_tampered"}, "00" * 32)
        h2_expected = hash_evidence({"phase": "second"}, h1_tampered)
        assert h2 != h2_expected
