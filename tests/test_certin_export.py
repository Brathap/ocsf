"""Tests for CERT-In Mandate Reporting & Schema Drift Monitor (Item 6).
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from main import app, storage_archive, drift_monitor
from certin_export import CertInReporter

ADMIN_KEY = "ulpf_admin_secret_key_2026"
OPERATOR_KEY = "ulpf_operator_key_2026"


class TestCertInAndDriftMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, headers={"X-API-Key": ADMIN_KEY})

    def test_certin_report_generation(self):
        """Verifies CERT-In standard incident report structure, fields, and SHA-256 seal."""
        # Ingest a security event
        rec = {
            "id": "certin-ev-001",
            "traceability": {
                "raw_sha256": "abcdef1234567890abcdef1234567890",
                "sanitized_raw": "Attack attempt detected from 198.51.100.23 targeting 10.0.0.1",
                "ingest_timestamp": "2026-09-27T10:00:00Z"
            },
            "normalized_data": {
                "class_uid": 4001,
                "category_name": "Network Activity",
                "severity": "Critical",
                "src_endpoint": {"ip": "198.51.100.23"},
                "dst_endpoint": {"ip": "10.0.0.1"},
                "compliance": {"pii_redacted": True}
            }
        }
        storage_archive.ingest_record(rec)
        storage_archive.flush()

        res = self.client.post("/api/certin/generate-report", json={
            "incident_id": "INC-2026-0091",
            "event_ids": ["certin-ev-001"],
            "remedial_action": "Egress connection dropped and attacker IP blacklisted."
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Check required CERT-In mandate fields
        self.assertIn("mandate_reference", data)
        self.assertIn("6-Hour", data.get("reporting_timeline", ""))
        self.assertIn("report_metadata", data)
        self.assertEqual(data["report_metadata"]["incident_id"], "INC-2026-0091")
        self.assertIn("report_integrity_sha256", data)
        self.assertEqual(len(data["report_integrity_sha256"]), 64)
        self.assertIn("198.51.100.23", data["incident_details"]["associated_indicators_of_compromise"]["source_ips"])

    def test_drift_monitor_alerting(self):
        """Verifies drift monitor threshold detection and flag triggering."""
        drift_monitor.clear_flags()

        # Ingest 30 events with high unmapped token count (simulating schema drift)
        for i in range(30):
            drift_monitor.record_inspection(
                event_id=f"drift-{i}",
                source_type="new_firewall_firmware_v2",
                unmapped_field_count=4, # unmapped attributes
                parsing_error=False
            )

        res = self.client.get("/api/drift/flags")
        self.assertEqual(res.status_code, 200)
        flags_data = res.json()

        self.assertGreater(flags_data["drift_stats"]["unmapped_ratio"], 0.15)
        self.assertGreaterEqual(len(flags_data["active_flags"]), 1)
        self.assertEqual(flags_data["active_flags"][0]["source_type"], "new_firewall_firmware_v2")


if __name__ == "__main__":
    unittest.main()
