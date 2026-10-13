#!/usr/bin/env python3
"""Adversarial Tamper Demonstration Script.

Simulates adversary tampering with an archived log in three stages:
1. Valid baseline: Generates an evidence bundle and verifies it.
2. Tamper Test A: Mutates a single byte in a stored raw event. Standalone verifier catches and rejects it.
3. Tamper Test B: Adversary attempts a full re-seal (recalculating the Merkle tree).
   Shows that re-sealing succeeds on a naive tree, but is mathematically CAUGHT
   when verified against an externally held head hash / signed checkpoint!
4. Honestly documents this cryptographic boundary.
"""

import os
import sys
import json
import base64
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from merkle_engine import MerkleTree, SignedMerkleCheckpoint


def run_tamper_demo():
    print("==========================================================================================")
    print("                    AEGISGUARD-ULPF FORENSIC TAMPER DEMONSTRATION                         ")
    print("==========================================================================================")

    # Keypair generation for signed enclave checkpoint
    priv_bytes, pub_bytes = SignedMerkleCheckpoint.generate_keypair()
    pub_hex = pub_bytes.hex()
    print(f"[*] Enclave Ed25519 Public Key: {pub_hex}")

    raw_events = [
        "Oct 06 09:00:01 firewall01 %ASA-4-106023: Denied tcp src 198.51.100.23/50901 dst 10.0.0.1/80",
        "Oct 06 09:00:02 auth sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 44321",
        "Oct 06 09:00:03 waf01 CEF:0|ArcSight|WAF|1.0|SQLi|SQL Injection Blocked|8|src=203.0.113.19 dst=10.0.0.2",
        "Oct 06 09:00:04 srx01 RT_FLOW_SESSION_DENY: 198.51.100.99/1234 -> 10.0.0.8/22"
    ]

    event_hashes = [hashlib.sha256(ev.encode("utf-8")).hexdigest() for ev in raw_events]
    tree = MerkleTree([h.encode("ascii") for h in event_hashes])
    original_root = tree.root_hex
    print(f"[*] Genuine Ledger Merkle Root: {original_root}")

    checkpoint = SignedMerkleCheckpoint.sign_root(original_root, len(raw_events), priv_bytes)

    # Build genuine bundle for event #0
    proof0 = tree.get_inclusion_proof(0)
    bundle_valid = {
        "merkle_checkpoint": checkpoint,
        "records": [{
            "traceability": {
                "raw_sha256": event_hashes[0],
                "raw_base64": base64.b64encode(raw_events[0].encode("utf-8")).decode("ascii"),
                "sanitized_raw": raw_events[0]
            },
            "merkle_proof": proof0,
            "merkle_root": original_root,
            "merkle_index": 0
        }]
    }

    bundle_path = "/tmp/ulpf_evidence_bundle.json"
    with open(bundle_path, "w", encoding="utf-8") as f:
        json.dump(bundle_valid, f, indent=2)

    print("\n--- STEP 1: Verify Genuine Evidence Bundle ---")
    ret = os.system(f"python3 verify_bundle.py {bundle_path} {pub_hex}")
    assert ret == 0, "Genuine bundle must pass verification"

    print("\n--- STEP 2: Adversary Modifies One Stored Raw Event Byte ---")
    tampered_bundle = json.loads(json.dumps(bundle_valid))
    # Alter IP in sanitized_raw / base64: change 198.51.100.23 to 198.51.100.99
    tampered_raw = raw_events[0].replace("198.51.100.23", "198.51.100.99")
    tampered_bundle["records"][0]["traceability"]["sanitized_raw"] = tampered_raw
    tampered_bundle["records"][0]["traceability"]["raw_base64"] = base64.b64encode(tampered_raw.encode("utf-8")).decode("ascii")

    with open(bundle_path, "w", encoding="utf-8") as f:
        json.dump(tampered_bundle, f, indent=2)

    ret = os.system(f"python3 verify_bundle.py {bundle_path} {pub_hex}")
    if ret != 0:
        print("[✓] PASS: Standalone verifier DETECTED single-byte raw record tampering!")

    print("\n--- STEP 3: Adversary Attempts Full Re-seal Attack ---")
    # Adversary recomputes SHA-256 and rebuilds Merkle tree over altered data
    tampered_sha = hashlib.sha256(tampered_raw.encode("utf-8")).hexdigest()
    fake_hashes = [tampered_sha] + event_hashes[1:]
    fake_tree = MerkleTree([h.encode("ascii") for h in fake_hashes])
    fake_root = fake_tree.root_hex
    fake_proof = fake_tree.get_inclusion_proof(0)

    tampered_bundle["records"][0]["traceability"]["raw_sha256"] = tampered_sha
    tampered_bundle["records"][0]["merkle_proof"] = fake_proof
    tampered_bundle["records"][0]["merkle_root"] = fake_root

    with open(bundle_path, "w", encoding="utf-8") as f:
        json.dump(tampered_bundle, f, indent=2)

    print(f"[*] Attacker forged internal Merkle Root: {fake_root}")
    print("[*] Verifying against externally held signed checkpoint...")
    ret = os.system(f"python3 verify_bundle.py {bundle_path} {pub_hex}")
    if ret != 0:
        print("[✓] PASS: Full re-seal attack was CAUGHT by externally signed enclave checkpoint!")

    print("\n==========================================================================================")
    print("                     HONEST CRYPTOGRAPHIC BOUNDARY STATEMENT                              ")
    print("==========================================================================================")
    print("1. If an adversary has write access to the host disk, they can edit logs and re-seal trees.")
    print("2. A re-sealed tree is indistinguishable from genuine without an EXTERNALLY HELD HEAD HASH")
    print("   or Ed25519 digital signature anchored outside the enclave (e.g. SOC HSM, external ledger).")
    print("3. AegisGuard-ULPF is TAMPER-EVIDENT, not magically tamper-immune against root host compromise.")
    print("==========================================================================================")


if __name__ == "__main__":
    run_tamper_demo()
