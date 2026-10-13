#!/usr/bin/env python3
"""Cryptographic Threat Intelligence Air-Gap Verification Utility (SIH 26156).

Verifies Ed25519 digital signatures on threat intelligence feeds prior to ingestion.
Protects air-gapped sovereign environments against threat intel supply chain poisoning.

Usage:
    python scripts/verify_threat_intel.py --feed path/to/threat_intel.json --sig path/to/threat_intel.json.sig --pubkey path/to/public.key
    python scripts/verify_threat_intel.py --generate-keys --out-dir keys/
"""

import os
import sys
import time
import datetime
import json
import base64
import argparse
from typing import Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("[ERROR] 'cryptography' library is required. Install via: pip install cryptography")
    sys.exit(1)


def generate_ed25519_keypair(out_dir: str = ".") -> Tuple[str, str]:
    """Generates an Ed25519 keypair and writes PEM/raw keys to disk."""
    os.makedirs(out_dir, exist_ok=True)
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    priv_path = os.path.join(out_dir, "threat_intel_ed25519_private.pem")
    pub_path = os.path.join(out_dir, "threat_intel_ed25519_public.pem")

    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    print(f"[+] Generated Ed25519 Private Key: {priv_path}")
    print(f"[+] Generated Ed25519 Public Key:  {pub_path}")
    return priv_path, pub_path


def load_public_key(pub_key_path: str) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from PEM, raw binary (32 bytes), or Base64."""
    with open(pub_key_path, "rb") as f:
        key_data = f.read().strip()

    if b"BEGIN PUBLIC KEY" in key_data:
        return serialization.load_pem_public_key(key_data)
    elif len(key_data) == 32:
        return ed25519.Ed25519PublicKey.from_public_bytes(key_data)
    else:
        # Try base64 decoding
        try:
            decoded = base64.b64decode(key_data)
            if len(decoded) == 32:
                return ed25519.Ed25519PublicKey.from_public_bytes(decoded)
        except Exception:
            pass
        return serialization.load_pem_public_key(key_data)


def sign_feed(feed_path: str, priv_key_path: str, out_sig_path: str) -> str:
    """Signs a threat intelligence JSON feed file using Ed25519."""
    with open(priv_key_path, "rb") as f:
        priv_bytes = f.read()

    priv_key = serialization.load_pem_private_key(priv_bytes, password=None)

    with open(feed_path, "rb") as f:
        feed_bytes = f.read()

    signature = priv_key.sign(feed_bytes)
    sig_b64 = base64.b64encode(signature).decode("ascii")

    with open(out_sig_path, "w", encoding="utf-8") as f:
        f.write(sig_b64)

    print(f"[+] Successfully signed {feed_path} -> {out_sig_path}")
    return out_sig_path


def verify_threat_intel_signature(feed_path: str, sig_path: str, pub_key_path: str) -> bool:
    """Verifies Ed25519 digital signature of threat intelligence feed before ingestion.

    Args:
        feed_path: Path to the threat feed JSON file.
        sig_path: Path to the .sig file (contains raw binary or Base64 Ed25519 signature).
        pub_key_path: Path to the trusted Ed25519 public key file.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    if not os.path.exists(feed_path):
        print(f"[ERROR] Feed file not found: {feed_path}")
        return False
    if not os.path.exists(sig_path):
        print(f"[ERROR] Signature file not found: {sig_path}")
        return False
    if not os.path.exists(pub_key_path):
        print(f"[ERROR] Public key file not found: {pub_key_path}")
        return False

    try:
        # 1. Load public key
        pub_key = load_public_key(pub_key_path)

        # 2. Read feed bytes exactly as stored (byte-for-byte fidelity)
        with open(feed_path, "rb") as f:
            feed_bytes = f.read()

        # 3. Read signature (support Base64 encoded or raw 64-byte binary)
        with open(sig_path, "rb") as f:
            sig_raw = f.read().strip()

        if len(sig_raw) == 64:
            sig_bytes = sig_raw
        else:
            try:
                sig_bytes = base64.b64decode(sig_raw)
            except Exception:
                sig_bytes = sig_raw

        # 4. Cryptographic verification using Ed25519
        pub_key.verify(sig_bytes, feed_bytes)

        # 5. Semantic validation of threat feed JSON and freshness check
        try:
            feed_json = json.loads(feed_bytes.decode("utf-8"))
            ioc_count = len(feed_json.get("iocs", feed_json.get("indicators", [])))
            
            # Freshness / Expiration verification if declared
            expires_at = feed_json.get("expires_at") or feed_json.get("valid_until")
            if expires_at:
                try:
                    import datetime
                    if isinstance(expires_at, (int, float)):
                        exp_ts = float(expires_at)
                    else:
                        exp_dt = datetime.datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                        exp_ts = exp_dt.timestamp()
                    if time.time() > exp_ts:
                        print(f"[CRITICAL ALERT] Threat feed has EXPIRED (expired at {expires_at}). Ingestion rejected.")
                        return False
                except Exception as exp_err:
                    print(f"[WARNING] Could not parse feed expiration timestamp: {exp_err}")

            print(f"[+] [AIR-GAP SECURITY] Cryptographic signature VALID. Feed integrity & authenticity confirmed.")
            print(f"[+] Feed Version: {feed_json.get('version', 'unknown')} | IOC Count: {ioc_count}")
        except json.JSONDecodeError:
            print(f"[+] [AIR-GAP SECURITY] Cryptographic signature VALID for binary feed artifact.")

        return True

    except InvalidSignature:
        print(f"[CRITICAL ALERT] Threat Intel Signature Verification FAILED! Untrusted or tampered feed.")
        return False
    except Exception as e:
        print(f"[ERROR] Signature verification error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Verify Ed25519 signature of threat intelligence feeds for ULPF air-gap security."
    )
    parser.add_argument("--feed", type=str, help="Path to threat intel JSON file")
    parser.add_argument("--sig", type=str, help="Path to .sig signature file")
    parser.add_argument("--pubkey", type=str, help="Path to Ed25519 public key PEM")
    parser.add_argument("--generate-keys", action="store_true", help="Generate new Ed25519 keypair")
    parser.add_argument("--sign", action="store_true", help="Sign a feed file with private key")
    parser.add_argument("--privkey", type=str, help="Private key for signing")
    parser.add_argument("--out-dir", type=str, default=".", help="Directory for key output")

    args = parser.parse_args()

    if args.generate_keys:
        generate_ed25519_keypair(args.out_dir)
        sys.exit(0)

    if args.sign:
        if not args.feed or not args.privkey:
            print("[ERROR] --sign requires --feed and --privkey")
            sys.exit(1)
        out_sig = args.sig or (args.feed + ".sig")
        sign_feed(args.feed, args.privkey, out_sig)
        sys.exit(0)

    if not args.feed or not args.sig or not args.pubkey:
        parser.print_help()
        sys.exit(1)

    is_valid = verify_threat_intel_signature(args.feed, args.sig, args.pubkey)
    if is_valid:
        print("[SUCCESS] Threat intel verified and cleared for ULPF ingestion.")
        sys.exit(0)
    else:
        print("[FAILURE] Ingestion aborted. Signature verification rejected.")
        sys.exit(1)


if __name__ == "__main__":
    main()
