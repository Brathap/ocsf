import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from main import app, storage_archive

ADMIN_KEY = "ulpf_admin_secret_key_2026"
client = TestClient(app)
AUTH_HEADERS = {"X-API-Key": ADMIN_KEY}


def test_merkle_endpoint_flow():
    # Ingest a known test event directly into storage_archive
    test_event = {
        "id": "merkle-test-event-001",
        "traceability": {
            "ingest_timestamp": "2026-09-27T12:00:00Z",
            "raw_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "sanitized_raw": "Sep 27 12:00:00 host kernel: [UFW BLOCK] IN=eth0 OUT=",
        },
        "normalized_data": {
            "class_uid": 4001,
            "category_name": "Network Activity",
            "activity_name": "Traffic Flow",
            "severity_id": 1,
            "severity": "Informational",
            "src_endpoint": {"ip": "192.168.1.50"},
            "dst_endpoint": {"ip": "10.0.0.1"},
            "enrichment": {"is_malicious": False, "threat_actor": "None"},
            "compliance": {"pii_redacted": False, "pii_redacted_types": []},
        }
    }
    storage_archive.ingest_record(test_event)
    storage_archive.flush()

    # 1. Fetch inclusion proof
    res = client.get(f"/api/merkle/proof/merkle-test-event-001", headers=AUTH_HEADERS)
    assert res.status_code == 200
    proof_data = res.json()
    assert proof_data["event_id"] == "merkle-test-event-001"
    assert "merkle_root" in proof_data
    assert "proof" in proof_data

    # 2. Verify legitimate proof via verification endpoint
    verify_payload = {
        "leaf_data": proof_data["leaf_data"],
        "leaf_index": proof_data["leaf_index"],
        "total_leaves": proof_data["total_leaves"],
        "proof": proof_data["proof"],
        "merkle_root": proof_data["merkle_root"]
    }
    v_res = client.post("/api/merkle/verify-proof", json=verify_payload, headers=AUTH_HEADERS)
    assert v_res.status_code == 200
    assert v_res.json()["verified"] is True
    assert v_res.json()["algorithm"] == "RFC-6962-SHA256"

    # 3. Verify that tampered leaf data fails verification
    tampered_payload = dict(verify_payload)
    tampered_payload["leaf_data"] = "merkle-test-event-001:2026-09-27T12:00:00Z:tampered_sha"
    fail_res = client.post("/api/merkle/verify-proof", json=tampered_payload, headers=AUTH_HEADERS)
    assert fail_res.status_code == 200
    assert fail_res.json()["verified"] is False
