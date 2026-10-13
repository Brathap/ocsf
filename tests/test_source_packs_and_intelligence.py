"""Tests for Declarative Source Packs, Unknown Source Intelligence, and Lineage Engine."""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from source_packs.registry import SourcePackRegistry
from unknown_engine.intelligence import FormatFingerprinter, TemplateClusterer, FieldInferencer, ProposalGenerator
from lineage_engine import LineageEngine
from drift_engine import DriftDetectionEngine


def test_declarative_source_pack_parsing():
    packs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sources"))
    registry = SourcePackRegistry(packs_dir)
    assert len(registry.packs) >= 3

    # Cisco ASA
    cisco_log = "%ASA-6-302013: Built inbound TCP connection 987654 for outside:198.51.100.4/443 (198.51.100.4/443) to inside:10.0.0.50/54321"
    routed = registry.route_and_parse(cisco_log)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Cisco"
    assert ocsf["src_endpoint"]["ip"] == "198.51.100.4"
    assert ocsf["dst_endpoint"]["ip"] == "10.0.0.50"
    assert ocsf["class_uid"] == 4001

    # CEF WAF
    cef_log = "CEF:0|ArcSight|WAF|1.0|SQLi|SQL Injection Attack|7|src=203.0.113.19 dst=10.0.0.10 spt=54123 dpt=80"
    routed_cef = registry.route_and_parse(cef_log)
    assert routed_cef is not None
    _, _, ocsf_cef = routed_cef
    assert ocsf_cef["src_endpoint"]["ip"] == "203.0.113.19"
    assert ocsf_cef["class_uid"] == 2001


def test_field_lineage_byte_spans():
    raw_log = "%ASA-6-302013: Built inbound TCP connection 987654 for outside:198.51.100.4/443 to inside:10.0.0.50/54321"
    ocsf_payload = {
        "class_uid": 4001,
        "src_endpoint": {"ip": "198.51.100.4"},
        "dst_endpoint": {"ip": "10.0.0.50"}
    }
    envelope = LineageEngine.build_envelope(raw_log, ocsf_payload, "cisco_asa", "9.16")
    fields = envelope["normalized_data"]["lineage"]["fields"]

    assert "src_endpoint.ip" in fields
    assert fields["src_endpoint.ip"]["raw_token"] == "198.51.100.4"
    start = fields["src_endpoint.ip"]["start"]
    end = fields["src_endpoint.ip"]["end"]
    assert raw_log[start:end] == "198.51.100.4"


def test_unknown_source_intelligence_offline():
    unknown_log = "2026-10-05T12:00:00Z mycustom-firewall alert src_ip=172.16.0.4 dst_ip=10.1.2.3 action=Blocked port 8080"
    
    fingerprint = FormatFingerprinter.identify(unknown_log)
    assert fingerprint["format"] == "KEY_VALUE"

    template = TemplateClusterer.extract_template(unknown_log)
    assert "<IP>" in template
    assert "<TIMESTAMP>" in template

    inferred = FieldInferencer.infer_fields(unknown_log)
    inferred_keys = [f["ocsf_field"] for f in inferred]
    assert "src_endpoint.ip" in inferred_keys
    assert "dst_endpoint.ip" in inferred_keys

    candidate_pack = ProposalGenerator.generate_candidate_pack("Acme", "Gateway", [unknown_log])
    assert "metadata:" in candidate_pack
    assert "ocsf:" in candidate_pack


def test_drift_detection_engine():
    drift = DriftDetectionEngine(coverage_drop_threshold=0.20)
    parser_id = "cisco_asa"

    # Establish normal baseline (4 fields extracted out of 4 expected)
    for _ in range(20):
        drift.record_parsing(parser_id, 4, 4, "normal log")
    
    status = drift.get_status()
    assert status["baselines"][parser_id] == 1.0

    # Simulate upstream vendor format change causing only 1 field out of 4 to be extracted
    for _ in range(15):
        drift.record_parsing(parser_id, 4, 1, "mutated vendor log")

    updated_status = drift.get_status()
    assert updated_status["total_alerts"] >= 1
    assert updated_status["recent_alerts"][0]["status"] == "DRIFT_DETECTED"
