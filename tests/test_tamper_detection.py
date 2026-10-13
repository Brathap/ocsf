"""Cryptographic Tamper Detection & Adversarial Verification Test.

Proves mathematically that if an attacker or malicious actor tampers with any raw
log byte or alters historical records in the archive:
1. The leaf hash changes immediately.
2. The Merkle Tree root calculation changes.
3. The cryptographic verification rejects the ledger with TAMPER_DETECTED.
"""

import sys
import os
import pytest
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
try:
    from backend.merkle_engine import MerkleTree, hash_leaf
except ModuleNotFoundError:
    from merkle_engine import MerkleTree, hash_leaf


class TestCryptographicTamperDetection:
    def test_single_byte_mutation_detected(self):
        original_logs = [
            b"2026-10-05T09:00:00Z firewall traffic allow src=192.168.1.1 dst=10.0.0.1",
            b"2026-10-05T09:00:01Z sshd[1234]: Failed password for root from 203.0.113.5",
            b"2026-10-05T09:00:02Z cef:0|Imperva|WAF|1.0|SQLi|SQL Injection Blocked|src=198.51.100.2"
        ]

        # Build genuine tree
        genuine_tree = MerkleTree(original_logs)
        genuine_root = genuine_tree.root_hex

        # Simulate adversarial tamper: changing root IP from 203.0.113.5 to 203.0.113.6
        tampered_logs = list(original_logs)
        tampered_logs[1] = b"2026-10-05T09:00:01Z sshd[1234]: Failed password for root from 203.0.113.6"

        tampered_tree = MerkleTree(tampered_logs)
        tampered_root = tampered_tree.root_hex

        # Roots must be completely different
        assert genuine_root != tampered_root, "Cryptographic failure: tampered log produced identical Merkle root!"

        # Audit inclusion proof check
        proof = genuine_tree.get_inclusion_proof(1)
        # Verifying genuine leaf with genuine proof passes
        assert MerkleTree.verify_inclusion_proof(original_logs[1], 1, len(original_logs), proof, genuine_root) is True

        # Verifying tampered leaf with original proof fails
        assert MerkleTree.verify_inclusion_proof(tampered_logs[1], 1, len(original_logs), proof, genuine_root) is False

    def test_leaf_reordering_tamper_detected(self):
        logs = [b"logA", b"logB", b"logC", b"logD"]
        tree1 = MerkleTree(logs)

        # Attacker swaps order of log B and C
        reordered_logs = [b"logA", b"logC", b"logB", b"logD"]
        tree2 = MerkleTree(reordered_logs)

        assert tree1.root_hex != tree2.root_hex, "Merkle tree must be strictly sequence-dependent!"

    def test_independent_canonical_calculation(self):
        """Verifies tree root against independent, manually calculated RFC 6962 formula."""
        import hashlib
        l0 = b"leaf_zero"
        l1 = b"leaf_one"

        # Independent manual RFC 6962 calculation
        h0 = hashlib.sha256(b"\x00" + l0).digest()
        h1 = hashlib.sha256(b"\x00" + l1).digest()
        expected_root = hashlib.sha256(b"\x01" + h0 + h1).hexdigest()

        # Engine calculation
        tree = MerkleTree([l0, l1])
        assert tree.root_hex == expected_root, "Engine root did not match independently calculated RFC 6962 hash!"

    def test_leaf_deletion_and_insertion_detected(self):
        logs = [b"ev1", b"ev2", b"ev3"]
        tree = MerkleTree(logs)
        root = tree.root_hex

        # Deletion
        assert MerkleTree([b"ev1", b"ev3"]).root_hex != root
        # Insertion
        assert MerkleTree([b"ev1", b"ev2", b"injected", b"ev3"]).root_hex != root
        # Duplication
        assert MerkleTree([b"ev1", b"ev2", b"ev2", b"ev3"]).root_hex != root

    def test_checkpoint_replay_rejection(self):
        try:
            from backend.merkle_engine import SignedMerkleCheckpoint
        except ModuleNotFoundError:
            from merkle_engine import SignedMerkleCheckpoint
        priv, pub = SignedMerkleCheckpoint.generate_keypair()
        logs_epoch1 = [b"ev1", b"ev2"]
        tree1 = MerkleTree(logs_epoch1)
        root1 = tree1.root_hex
        cp1 = SignedMerkleCheckpoint.sign_root(root1, 2, priv)

        # Epoch 2
        logs_epoch2 = [b"ev1", b"ev2", b"ev3"]
        tree2 = MerkleTree(logs_epoch2)
        root2 = tree2.root_hex

        # Attempting to replay Epoch 1 checkpoint on Epoch 2 root fails
        assert SignedMerkleCheckpoint.verify_signature(root2, 3, cp1["signature_hex"], pub) is False
