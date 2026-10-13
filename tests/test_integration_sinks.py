"""Tests for Integration Sinks: Parquet, NDJSON, Splunk HEC, Elastic Bulk, and Syslog."""

import os
import sys
import json
import socket
import pytest
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from integration_sinks import ParquetSink, NDJSONSink, SplunkHECSink, ElasticBulkSink, SyslogForwarderSink, HAS_PYARROW

SAMPLE_RECORDS = [
    {
        "id": "evt-001",
        "timestamp": 1728210000.0,
        "traceability": {"raw_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"},
        "normalized_data": {
            "class_uid": 4001,
            "category_name": "Network Activity",
            "activity_name": "Traffic Deny",
            "severity_id": 4,
            "severity": "High",
            "src_endpoint": {"ip": "198.51.100.23", "port": 50901},
            "dst_endpoint": {"ip": "10.0.0.1", "port": 80},
            "connection_info": {"protocol_name": "TCP"},
            "user": {"name": "test_user"},
            "unmapped": {"vendor_rule": "R10"}
        }
    }
]


def test_parquet_export_and_footer_contract():
    if not HAS_PYARROW:
        pytest.skip("pyarrow not installed")
    import pyarrow.parquet as pq

    with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        out_path = ParquetSink.export(SAMPLE_RECORDS, tmp_path)
        assert os.path.exists(out_path)
        
        # Read back and verify footer contract
        table = pq.read_table(out_path)
        assert len(table) == 1
        assert table.schema.metadata.get(b"ulpf_schema_version") == b"1.1.0-ocsf-contract"
        assert table.schema.metadata.get(b"ocsf_version") == b"1.1.0"
        
        # Verify columns
        pydict = table.to_pydict()
        assert pydict["src_endpoint_ip"][0] == "198.51.100.23"
        assert pydict["dst_endpoint_port"][0] == 80
        assert pydict["class_uid"][0] == 4001
        assert "vendor_rule" in pydict["unmapped_json"][0]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_ndjson_export():
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        out_path = NDJSONSink.export(SAMPLE_RECORDS, tmp_path)
        with open(out_path, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 1
        assert lines[0]["id"] == "evt-001"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


class MockReceiverHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)
        self.server.last_body = body
        self.server.last_auth = self.headers.get("Authorization", "")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"success"}')

    def log_message(self, format, *args):
        pass  # Quiet mock


def test_splunk_hec_sink_mock():
    server = HTTPServer(("127.0.0.1", 0), MockReceiverHandler)
    server.last_body = b""
    server.last_auth = ""
    port = server.server_address[1]
    t = threading.Thread(target=server.handle_request)
    t.start()

    sink = SplunkHECSink(f"http://127.0.0.1:{port}/services/collector", token="splunk-token-123")
    res = sink.send_batch(SAMPLE_RECORDS)
    t.join()

    assert res["status"] == 200
    assert "Splunk splunk-token-123" in server.last_auth
    assert b"ulpf:ocsf" in server.last_body
    server.server_close()


def test_elastic_bulk_sink_mock():
    server = HTTPServer(("127.0.0.1", 0), MockReceiverHandler)
    server.last_body = b""
    port = server.server_address[1]
    t = threading.Thread(target=server.handle_request)
    t.start()

    sink = ElasticBulkSink(f"http://127.0.0.1:{port}")
    res = sink.send_batch(SAMPLE_RECORDS)
    t.join()

    assert res["status"] == 200
    assert b'_index": "ulpf-ocsf-logs' in server.last_body or b'_index":"ulpf-ocsf-logs' in server.last_body
    server.server_close()


def test_syslog_forwarder_sink():
    # Setup test UDP listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.settimeout(2.0)

    sink = SyslogForwarderSink("127.0.0.1", port, protocol="udp")
    sink.forward_event("CEF:0|ArcSight|WAF|1.0|SQLi|SQL Injection|7|src=1.2.3.4")

    data, _ = sock.recvfrom(1024)
    assert b"CEF:0|ArcSight" in data
    sock.close()
