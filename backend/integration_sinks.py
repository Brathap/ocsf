"""Integration Sinks & Parquet Export Engine for ULPF.

Supports downstream enterprise data lake & SIEM integrations:
1. Parquet Lakehouse Exporter: Strongly typed column contract with schema version in file metadata.
2. NDJSON Bulk Exporter: Line-delimited OCSF stream.
3. Splunk HEC (HTTP Event Collector) Forwarder: Batched HTTP POST with bearer token.
4. Elastic Bulk API Forwarder: ndjson action + payload indexing.
5. Syslog CEF / LEEF Forwarder: Formatted socket forwarder for SIEM ingestion.
"""

import os
import sys
try:
    import safe_serializer as json
except ImportError:
    from . import safe_serializer as json
import time
import socket
from typing import List, Dict, Any, Optional

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False

PARQUET_SCHEMA_VERSION = "1.1.0-ocsf-contract"


class ParquetSink:
    """Exports normalized OCSF records to Apache Parquet with a fixed column contract."""

    # Explicit canonical schema for SOC Lakehouse / Spark / Trino querying
    CANONICAL_SCHEMA = pa.schema([
        ("event_id", pa.string()),
        ("timestamp", pa.float64()),
        ("raw_sha256", pa.string()),
        ("class_uid", pa.int32()),
        ("category_name", pa.string()),
        ("activity_name", pa.string()),
        ("severity_id", pa.int32()),
        ("severity", pa.string()),
        ("src_endpoint_ip", pa.string()),
        ("src_endpoint_port", pa.int32()),
        ("dst_endpoint_ip", pa.string()),
        ("dst_endpoint_port", pa.int32()),
        ("protocol_name", pa.string()),
        ("user_name", pa.string()),
        ("unmapped_json", pa.string()),
    ], metadata={
        b"ulpf_schema_version": PARQUET_SCHEMA_VERSION.encode("utf-8"),
        b"ocsf_version": b"1.1.0"
    }) if HAS_PYARROW else None

    @classmethod
    def export(cls, records: List[Dict[str, Any]], output_filepath: str) -> str:
        if not HAS_PYARROW:
            raise RuntimeError("pyarrow library is required for Parquet export.")

        data: Dict[str, list] = {col.name: [] for col in cls.CANONICAL_SCHEMA}

        for r in records:
            norm = r.get("normalized_data", {})
            trace = r.get("traceability", {})

            data["event_id"].append(str(r.get("id", "")))
            data["timestamp"].append(float(r.get("timestamp", time.time())))
            data["raw_sha256"].append(str(trace.get("raw_sha256", "")))
            data["class_uid"].append(int(norm.get("class_uid", 6001)))
            data["category_name"].append(str(norm.get("category_name", "Application Activity")))
            data["activity_name"].append(str(norm.get("activity_name", "event")))
            data["severity_id"].append(int(norm.get("severity_id", 1)))
            data["severity"].append(str(norm.get("severity", "Informational")))

            src = norm.get("src_endpoint", {})
            data["src_endpoint_ip"].append(str(src.get("ip")) if src.get("ip") else None)
            data["src_endpoint_port"].append(int(src["port"]) if src.get("port") and str(src["port"]).isdigit() else None)

            dst = norm.get("dst_endpoint", {})
            data["dst_endpoint_ip"].append(str(dst.get("ip")) if dst.get("ip") else None)
            data["dst_endpoint_port"].append(int(dst["port"]) if dst.get("port") and str(dst["port"]).isdigit() else None)

            conn = norm.get("connection_info", {})
            data["protocol_name"].append(str(conn.get("protocol_name")) if conn.get("protocol_name") else None)

            user = norm.get("user", {})
            data["user_name"].append(str(user.get("name")) if user.get("name") else None)

            unmapped = norm.get("unmapped", {})
            data["unmapped_json"].append(json.dumps(unmapped) if unmapped else None)

        table = pa.Table.from_pydict(data, schema=cls.CANONICAL_SCHEMA)
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        pq.write_table(table, output_filepath, compression="snappy")
        return output_filepath


class NDJSONSink:
    """Exports records as standard newline-delimited JSON for Kafka or SIEM streaming."""

    @staticmethod
    def export(records: List[Dict[str, Any]], output_filepath: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return output_filepath


class SplunkHECSink:
    """Batched forwarder for Splunk HTTP Event Collector (HEC)."""

    def __init__(self, endpoint_url: str, token: str, timeout: float = 5.0):
        self.endpoint_url = endpoint_url
        self.token = token
        self.timeout = timeout

    def send_batch(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        import urllib.request
        payload_lines = []
        for r in records:
            splunk_event = {
                "time": r.get("timestamp", time.time()),
                "host": "ulpf-collector",
                "source": "ulpf:ocsf",
                "sourcetype": "_json",
                "event": r
            }
            payload_lines.append(json.dumps(splunk_event))
        body = "\n".join(payload_lines).encode("utf-8")

        req = urllib.request.Request(
            self.endpoint_url,
            data=body,
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return {"status": resp.status, "bytes_sent": len(body)}


class ElasticBulkSink:
    """Forwarder for Elasticsearch / OpenSearch Bulk API."""

    def __init__(self, endpoint_url: str, index_name: str = "ulpf-ocsf-logs", timeout: float = 5.0):
        self.endpoint_url = endpoint_url.rstrip("/") + "/_bulk"
        self.index_name = index_name
        self.timeout = timeout

    def send_batch(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        import urllib.request
        lines = []
        for r in records:
            action = {"index": {"_index": self.index_name}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(r))
        body = ("\n".join(lines) + "\n").encode("utf-8")

        req = urllib.request.Request(
            self.endpoint_url,
            data=body,
            headers={"Content-Type": "application/x-ndjson"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return {"status": resp.status, "records_sent": len(records)}


class SyslogForwarderSink:
    """Syslog CEF / LEEF standard forwarder."""

    def __init__(self, host: str, port: int, protocol: str = "udp"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()

    def forward_event(self, raw_line: str):
        data = raw_line.encode("utf-8") + b"\n"
        if self.protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (self.host, self.port))
            sock.close()
        elif self.protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            sock.sendall(data)
            sock.close()
