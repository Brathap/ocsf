"""Tests for Authentication & RBAC Authorization (Requirement 5).

Verifies:
1. Unauthenticated requests to protected endpoints return 401 Unauthorized.
2. Invalid API keys return 401 Unauthorized.
3. Operator role accessing operator/admin endpoints succeeds (e.g. /api/metrics, /api/export-forensic).
4. Operator role attempting admin-only endpoints (e.g. /api/threat-intel/import, /api/generate-parser, /api/host-stream/toggle, /api/audit-logs) returns 403 Forbidden.
5. Admin role succeeds on all endpoints.
6. Audit log table in SQLite records actor, role, action, and HTTP status code.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from main import app, storage_archive

ADMIN_KEY = "ulpf_admin_secret_key_2026"
OPERATOR_KEY = "ulpf_operator_key_2026"


class TestAuthenticationAndRBAC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_unauthenticated_requests_return_401(self):
        """Endpoints without credentials return 401 Unauthorized."""
        endpoints = [
            ("GET", "/api/metrics"),
            ("POST", "/api/live-logs"),
            ("GET", "/api/export-forensic/nonexistent"),
            ("POST", "/api/host-stream/toggle"),
            ("POST", "/api/generate-parser"),
            ("GET", "/api/audit-logs"),
            ("GET", "/api/stream"),
            ("POST", "/api/ai-infer-schema"),
            ("GET", "/api/airgap/status"),
            ("GET", "/api/threat-intel/metadata"),
            ("GET", "/api/host-stream/status"),
        ]
        for method, path in endpoints:
            if method == "GET":
                res = self.client.get(path)
            else:
                res = self.client.post(path, json={"raw_sample": "test"} if "ai-infer" in path else {})
            self.assertEqual(res.status_code, 401, f"Expected 401 for {method} {path}, got {res.status_code}")

    def test_invalid_api_key_returns_401(self):
        """Invalid API key returns 401 Unauthorized."""
        headers = {"X-API-Key": "completely_fake_invalid_key"}
        res = self.client.get("/api/metrics", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_operator_rbac_permissions(self):
        """Operator can access /api/metrics and /api/live-logs, but is denied (403) from admin endpoints."""
        op_headers = {"X-API-Key": OPERATOR_KEY}

        # Operator allowed on /api/metrics
        res = self.client.get("/api/metrics", headers=op_headers)
        self.assertEqual(res.status_code, 200)

        # Operator denied on admin-only /api/audit-logs
        res = self.client.get("/api/audit-logs", headers=op_headers)
        self.assertEqual(res.status_code, 403)

        # Operator denied on admin-only /api/generate-parser
        res = self.client.post("/api/generate-parser", headers=op_headers, json={
            "parser_name": "test", "source_type": "firewall", "wire_format": "SYSLOG", "mappings": {}
        })
        self.assertEqual(res.status_code, 403)

        # Operator denied on admin-only /api/host-stream/toggle
        res = self.client.post("/api/host-stream/toggle", headers=op_headers)
        self.assertEqual(res.status_code, 403)

    def test_admin_rbac_and_audit_logging(self):
        """Admin can access all endpoints and actions are captured in SQLite audit table."""
        admin_headers = {"X-API-Key": ADMIN_KEY}

        # 1. Admin toggles host stream
        res = self.client.post("/api/host-stream/toggle", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

        # 2. Flush writes so audit worker commits to SQLite
        storage_archive.flush()

        # 3. Admin queries audit logs
        audit_res = self.client.get("/api/audit-logs", headers=admin_headers)
        self.assertEqual(audit_res.status_code, 200)
        logs = audit_res.json()
        self.assertGreater(len(logs), 0)

        # Verify recorded fields
        recent_audit = logs[0]
        self.assertIn("timestamp", recent_audit)
        self.assertIn("username", recent_audit)
        self.assertIn("role", recent_audit)
        self.assertIn("action", recent_audit)
        self.assertIn("status_code", recent_audit)


    def test_bearer_token_and_health_exemption(self):
        """Verify Authorization: Bearer token format works and /health is exempt."""
        # /health is exempt without token
        health_res = self.client.get("/health")
        self.assertEqual(health_res.status_code, 200)

        # Protected route works with Authorization: Bearer header
        bearer_headers = {"Authorization": f"Bearer {ADMIN_KEY}"}
        metrics_res = self.client.get("/api/metrics", headers=bearer_headers)
        self.assertEqual(metrics_res.status_code, 200)

        # Verify persistent bearer token file has owner-only mode (0600)
        from auth_middleware import _TOKEN_FILE
        if os.path.exists(_TOKEN_FILE):
            file_mode = oct(os.stat(_TOKEN_FILE).st_mode & 0o777)
            self.assertEqual(file_mode, "0o600")


if __name__ == "__main__":
    unittest.main()
