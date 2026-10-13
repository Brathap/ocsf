import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
try:
    from backend.merkle_engine import MerkleTree, hash_leaf, hash_children
except ModuleNotFoundError:
    from merkle_engine import MerkleTree, hash_leaf, hash_children


def test_merkle_tree_empty():
    tree = MerkleTree([])
    assert tree.root is None
    assert tree.root_hex == ""
    assert tree.get_inclusion_proof(0) is None


def test_merkle_tree_single_leaf():
    data = b"event_payload_alpha"
    tree = MerkleTree([data])
    assert tree.root == hash_leaf(data)
    proof = tree.get_inclusion_proof(0)
    assert proof == []
    assert MerkleTree.verify_inclusion_proof(data, 0, 1, proof, tree.root_hex) is True
    # Tampered leaf should fail
    assert MerkleTree.verify_inclusion_proof(b"tampered_alpha", 0, 1, proof, tree.root_hex) is False


def test_merkle_tree_multi_leaves():
    leaves = [
        b"event_1_login_attempt",
        b"event_2_firewall_drop",
        b"event_3_certin_alert",
        b"event_4_privilege_escalation",
        b"event_5_port_scan_detected",
    ]
    tree = MerkleTree(leaves)
    assert tree.root is not None

    for idx, leaf in enumerate(leaves):
        proof = tree.get_inclusion_proof(idx)
        assert proof is not None
        # Valid proof
        assert MerkleTree.verify_inclusion_proof(leaf, idx, len(leaves), proof, tree.root_hex) is True
        # Malicious substitution fails
        assert MerkleTree.verify_inclusion_proof(b"evil_record", idx, len(leaves), proof, tree.root_hex) is False
        # Wrong root fails
        assert MerkleTree.verify_inclusion_proof(leaf, idx, len(leaves), proof, "deadbeef" * 8) is False


def test_merkle_domain_separation():
    # RFC 6962 leaf vs child collision resistance
    data = b"identical_bytes"
    leaf_h = hash_leaf(data)
    # Interior node prefix is 0x01, leaf is 0x00
    assert leaf_h != hash_children(data, b"")
