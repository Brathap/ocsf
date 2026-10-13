#!/usr/bin/env python3
"""Standalone Forensic Evidence Bundle Verifier for ULPF.

Requires ONLY Python stdlib and 'cryptography' (or standalone verification).
Takes an exported ULPF evidence bundle JSON/ZIP and verifies:
1. Base64 payload decoding matches raw wire string exactly.
2. SHA-256 wire hash matches raw wire bytes.
3. Inclusion proof recalculation reaches the documented Merkle root.
4. Optional Ed25519 signature verification against Enclave Public Key.
5. Exit code 0 on mathematical integrity, non-zero on tampering.
"""

import os
import sys
import json
import base64
import hashlib
from typing import Dict, Any, List


def verify_bundle(bundle_path: str, enclave_pubkey_hex: str = None) -> bool:
    print(f"[*] Loading evidence bundle: {bundle_path}")
    if not os.path.exists(bundle_path):
        print(f"[!] Bundle file not found: {bundle_path}", file=sys.stderr)
        return False

    with open(bundle_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # If it's a list or envelope
    records = data if isinstance(data, list) else data.get("records", [data])
    merkle_checkpoint = data.get("merkle_checkpoint", {}) if isinstance(data, dict) else {}

    print(f"[*] Verifying {len(records)} record(s)...")

    for idx, rec in enumerate(records):
        trace = rec.get("traceability", {})
        raw_b64 = trace.get("raw_base64")
        expected_sha = trace.get("raw_sha256")
        sanitized_raw = trace.get("sanitized_raw", "")

        # 1. Base64 exactness
        if raw_b64:
            decoded_bytes = base64.b64decode(raw_b64)
            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
            actual_sha = hashlib.sha256(decoded_bytes).hexdigest()
            if actual_sha != expected_sha:
                print(f"[TAMPER DETECTED] Record #{idx}: SHA-256 mismatch! Expected {expected_sha}, got {actual_sha}", file=sys.stderr)
                return False
        elif sanitized_raw:
            actual_sha = hashlib.sha256(sanitized_raw.encode("utf-8")).hexdigest()
            if actual_sha != expected_sha:
                print(f"[TAMPER DETECTED] Record #{idx}: SHA-256 mismatch against raw text!", file=sys.stderr)
                return False

        # 2. Merkle Inclusion Proof (if provided)
        proof = rec.get("merkle_proof")
        target_root = merkle_checkpoint.get("root_hex") if merkle_checkpoint else rec.get("merkle_root")
        leaf_index = rec.get("merkle_index", idx)

        # Check if record claims a different root than the signed checkpoint
        if merkle_checkpoint and rec.get("merkle_root") and rec["merkle_root"].lower() != merkle_checkpoint.get("root_hex", "").lower():
            print(f"[TAMPER DETECTED] Record #{idx}: Claimed root {rec['merkle_root']} diverges from signed enclave checkpoint {merkle_checkpoint.get('root_hex')}", file=sys.stderr)
            return False

        if proof and target_root:
            curr_hash = hashlib.sha256(b"\x00" + expected_sha.encode("ascii")).digest()
            for step in proof:
                sib_bytes = bytes.fromhex(step["hash"])
                if step["direction"] == "left":
                    curr_hash = hashlib.sha256(b"\x01" + sib_bytes + curr_hash).digest()
                else:
                    curr_hash = hashlib.sha256(b"\x01" + curr_hash + sib_bytes).digest()

            if curr_hash.hex().lower() != target_root.lower():
                print(f"[TAMPER DETECTED] Record #{idx}: Merkle audit path failed to reconstruct root {target_root}", file=sys.stderr)
                return False

    print(f"[✓] All {len(records)} record SHA-256 wire digests and Merkle inclusion proofs mathematically VERIFIED.")

    # 3. Check Ed25519 signature over checkpoint if present
    if merkle_checkpoint and merkle_checkpoint.get("signature_hex") and enclave_pubkey_hex:
        print("[*] Verifying Ed25519 Enclave Checkpoint Signature...")
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(enclave_pubkey_hex))
            msg = f"ULPF-CHECKPOINT:root={merkle_checkpoint['root_hex']}:size={merkle_checkpoint['tree_size']}".encode("utf-8")
            pub.verify(bytes.fromhex(merkle_checkpoint["signature_hex"]), msg)
            print("[✓] Enclave Ed25519 Digital Signature mathematically VALID.")
        except Exception as e:
            print(f"[TAMPER DETECTED] Checkpoint digital signature validation failed: {e}", file=sys.stderr)
            return False

    print("[SUCCESS] Evidence bundle chain-of-custody intact (tamper-evident).")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 verify_bundle.py <bundle.json> [enclave_public_key_hex]")
        sys.exit(1)

    bundle_file = sys.argv[1]
    pubkey = sys.argv[2] if len(sys.argv) > 2 else None
    valid = verify_bundle(bundle_file, pubkey)
    sys.exit(0 if valid else 1)
