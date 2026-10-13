"""Tests for Forensic Evidence Bundle Generator (Requirement 7).

Verifies:
1. Manifest header accurately specifies "SHA-256 INTEGRITY-HASHED BUNDLE" (no false RFC 3161 claim).
2. ZIP evidence bundle unpacks cleanly.
3. Contains raw_event.wire, ocsf_event.json, manifest.sha256, and verification_audit.txt.
4. SHA-256 checksums in the manifest match the exact bytes of raw_event.wire and ocsf_event.json.
"""

import hashlib
import io
import os
import sys
import unittest
import zipfile
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from main import app, storage_archive

ADMIN_KEY = "ulpf_admin_secret_key_2026"


class TestForensicEvidenceBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, headers={"X-API-Key": ADMIN_KEY})

    def test_forensic_bundle_structure_and_hashes(self):
        """Verifies ZIP evidence bundle packaging and SHA-256 manifest integrity."""
        # 1. Ingest a known event
        raw = "Oct 24 10:20:30 host1 sshd[1234]: Failed password for invalid user admin from 198.51.100.23 port 54321 ssh2"
        record = {
            "id": "forensic-test-event-001",
            "traceability": {
                "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "raw_base64": "b64payload",
                "ingest_timestamp": "2026-09-26T12:00:00Z",
                "sanitized_raw": raw,
            },
            "normalized_data": {
                "class_uid": 3002,
                "category_name": "Identity & Access Management",
                "activity_name": "User Authentication",
                "severity_id": 4,
                "severity": "High",
                "src_endpoint": {"ip": "198.51.100.23"},
                "dst_endpoint": {"ip": "127.0.0.1"},
            }
        }
        storage_archive.ingest_record(record)
        storage_archive.flush()

        # 2. Download bundle
        res = self.client.get("/api/export-forensic/forensic-test-event-001")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("content-type"), "application/zip")

        # 3. Unpack in-memory ZIP
        zip_buf = io.BytesIO(res.content)
        with zipfile.ZipFile(zip_buf, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("raw_event.wire", namelist)
            self.assertIn("ocsf_event.json", namelist)
            self.assertIn("manifest.sha256", namelist)
            self.assertIn("verification_audit.txt", namelist)

            raw_wire = zf.read("raw_event.wire").decode("utf-8")
            ocsf_json = zf.read("ocsf_event.json").decode("utf-8")
            manifest = zf.read("manifest.sha256").decode("utf-8")

            # 4. Verify no RFC 3161 false claim is present in manifest
            self.assertNotIn("RFC 3161", manifest)
            self.assertIn("SHA-256 INTEGRITY-HASHED BUNDLE", manifest)

            # 5. Verify cryptographic checksums match exact file bytes
            computed_raw_sha = hashlib.sha256(raw_wire.encode("utf-8")).hexdigest()
            computed_ocsf_sha = hashlib.sha256(ocsf_json.encode("utf-8")).hexdigest()

            self.assertIn(computed_raw_sha, manifest)
            self.assertIn(computed_ocsf_sha, manifest)


if __name__ == "__main__":
    unittest.main()
