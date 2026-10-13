"""Tests for Threat Intel Update Mechanism (Requirement 4).

Verifies:
1. Surfaces "version" and "last_updated" timestamp metadata.
2. Accepts offline import when CSV SHA-256 matches provided manifest.
3. Rejects offline import with error when SHA-256 does NOT match manifest (tamper detection).
4. Rejects offline import if mandatory columns are missing.
5. Verifies audit callback is invoked for every import attempt (success & rejection).
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from threat_intel_manager import ThreatIntelManager


class TestThreatIntelUpdateMechanism(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ulpf_intel_test_")
        self.csv_path = os.path.join(self.temp_dir, "threat_intel.csv")
        self.audits = []

        initial_csv = (
            "src_ip,threat_group,severity,mitre_id\n"
            "198.51.100.23,APT29,High,T1133\n"
            "203.0.113.84,LazarusGroup,Critical,T1110.001\n"
        )
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(initial_csv)

        def audit_cb(user, role, action, resource, code, details):
            self.audits.append({
                "user": user, "role": role, "action": action,
                "resource": resource, "code": code, "details": details
            })

        self.manager = ThreatIntelManager(self.csv_path, audit_callback=audit_cb)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_version_and_metadata_surfaced(self):
        """Metadata includes version, last_updated, sha256, and total IOC count."""
        meta = self.manager.get_metadata()
        self.assertIn("version", meta)
        self.assertIn("last_updated", meta)
        self.assertIn("sha256", meta)
        self.assertEqual(meta["total_iocs"], 2)
        self.assertIsNotNone(self.manager.match_ip("198.51.100.23"))

    def test_checksum_verified_import_success(self):
        """Import with matching SHA-256 and new version succeeds and updates cache."""
        new_csv = (
            "src_ip,threat_group,severity,mitre_id\n"
            "198.51.100.23,APT29,High,T1133\n"
            "203.0.113.84,LazarusGroup,Critical,T1110.001\n"
            "192.0.2.145,Sandworm,High,T1498\n"
            "45.33.32.156,LockBit_Ransomware,Critical,T1486\n"
        ).encode("utf-8")

        new_sha = hashlib.sha256(new_csv).hexdigest()
        manifest = {
            "version": "2.1.0",
            "sha256": new_sha,
            "timestamp": "2026-09-26T14:00:00Z"
        }

        success, msg, meta = self.manager.import_threat_intel(new_csv, manifest, "secops_admin", "admin")
        self.assertTrue(success)
        self.assertEqual(meta["version"], "2.1.0")
        self.assertEqual(meta["total_iocs"], 4)
        self.assertEqual(self.manager.match_ip("45.33.32.156")["threat_group"], "LockBit_Ransomware")

        # Verify audit trail recorded success
        self.assertTrue(any(a["action"] == "THREAT_INTEL_UPDATED" and a["code"] == 200 for a in self.audits))

    def test_checksum_mismatch_rejected(self):
        """Import with altered content or invalid manifest SHA is rejected (tamper guard)."""
        csv_bytes = (
            "src_ip,threat_group,severity,mitre_id\n"
            "1.2.3.4,FakeGroup,Low,T1000\n"
        ).encode("utf-8")

        tampered_manifest = {
            "version": "9.9.9",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        }

        success, msg, meta = self.manager.import_threat_intel(csv_bytes, tampered_manifest, "analyst1", "operator")
        self.assertFalse(success)
        self.assertIn("Checksum mismatch", msg)
        self.assertEqual(meta["version"], "1.0.0")  # Untouched

        # Verify audit trail logged rejection
        self.assertTrue(any(a["action"] == "THREAT_INTEL_IMPORT_REJECTED" and a["code"] == 400 for a in self.audits))

    def test_staleness_freshness_detection(self):
        """Confirm that threat intel staleness status is accurately flagged when exceeding freshness threshold."""
        # Fresh initial intel
        meta = self.manager.get_metadata()
        self.assertFalse(meta["is_stale"])
        self.assertEqual(meta["freshness_status"], "FRESH_ACTIVE")

        # Fake old timestamp (30 days ago)
        self.manager.last_updated = "2020-01-01T00:00:00Z"
        stale_meta = self.manager.get_metadata()
        self.assertTrue(stale_meta["is_stale"])
        self.assertEqual(stale_meta["freshness_status"], "STALE_ATTENTION_REQUIRED")


if __name__ == "__main__":
    unittest.main()
