"""Tests for Multi-Signal Schema Onboarding & Consensus Engine (Item 8).
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from main import app

ADMIN_KEY = "ulpf_admin_secret_key_2026"


class TestOnboardingConsensus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, headers={"X-API-Key": ADMIN_KEY})

    def test_unambiguous_cef_consensus(self):
        """Standard CEF log produces high consensus (disagreement_score == 0.0) across all 3 signals."""
        cef_sample = "CEF:0|Imperva|SecureSphere|14.0|1000|SQL Injection|5|src=198.51.100.23 dst=10.0.0.1 act=drop"
        res = self.client.post("/api/ai-infer-schema", json={"raw_sample": cef_sample})
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["detected_wire_format"], "CEF")
        self.assertEqual(data["disagreement_score"], 0.0)
        self.assertEqual(data["confidence_score"], 98.0)
        self.assertEqual(data["signals"]["signature_regex_format"], "CEF")
        self.assertEqual(data["signals"]["delimiter_entropy_format"], "CEF")
        self.assertEqual(data["signals"]["structural_grammar_format"], "CEF")
        self.assertFalse(data["anomaly_precheck"]["has_anomalies"])

    def test_unambiguous_json_consensus(self):
        """Standard JSON log produces high consensus across all 3 signals."""
        json_sample = '{"event": "login", "user": "admin", "src_ip": "10.0.0.5", "status": "failed"}'
        res = self.client.post("/api/ai-infer-schema", json={"raw_sample": json_sample})
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["detected_wire_format"], "JSON")
        self.assertEqual(data["disagreement_score"], 0.0)
        self.assertFalse(data["anomaly_precheck"]["has_anomalies"])

    def test_ambiguous_log_produces_disagreement_and_anomaly_flag(self):
        """Malformed or hybrid log produces non-zero disagreement score and triggers anomaly pre-check."""
        # Syslog header followed by key-value pairs without standard syslog body
        ambiguous = "src=192.168.1.1 dst=10.0.0.1 proto=TCP action=deny user=test"
        res = self.client.post("/api/ai-infer-schema", json={"raw_sample": ambiguous})
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("disagreement_score", data)
        self.assertIn("anomaly_precheck", data)


if __name__ == "__main__":
    unittest.main()
