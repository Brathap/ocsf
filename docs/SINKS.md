# SIH 26156 Integration Sinks Contract & Architecture
**Document:** `docs/SINKS.md`  
**Standard:** OCSF v1.1.0 Canonical Projection  
**Schema Contract Version:** `1.1.0-ocsf-contract`

---

## 1. Overview of Downstream Integration Sinks

AegisGuard-ULPF serves as the high-velocity sovereign evidentiary layer in front of enterprise security lakes and SIEMs. Normalized telemetry is emitted through five deterministic integration sinks:

| Sink Type | Target Platform | Wire Protocol | Delivery Semantics | Schema Contract |
|:---|:---|:---|:---|:---|
| **Parquet Lakehouse** | Trino, Apache Spark, Snowflake, AWS Athena | Native Parquet file | Compressed Batches (Snappy) | Pinned 15-column schema with schema version in footer |
| **NDJSON Bulk Stream** | Local storage, Kafka, Vector, Logstash | Newline-delimited JSON | Stream / Rotating Files | Full OCSF envelope + lineage |
| **Splunk HEC** | Splunk Enterprise & Splunk Cloud | HTTP POST `/services/collector` | Batched HTTP (Bearer token) | Standard `event: _json` |
| **Elasticsearch Bulk** | Elasticsearch & OpenSearch | HTTP POST `/_bulk` | Batched ndjson index actions | Direct OCSF index mapping |
| **Syslog Forwarder** | QRadar, ArcSight, legacy SIEMs | RFC 5424 / RFC 3164 (UDP/TCP/TLS) | Line-stream | CEF / LEEF standard |

---

## 2. Parquet Schema Contract (SOC Data Lake)

The Parquet export sink (`backend/integration_sinks.py`) enforces a fixed column schema with metadata versioning:

```
Table Schema:
├── event_id          : string (UUID / deterministic hash)
├── timestamp         : double (epoch seconds)
├── raw_sha256        : string (SHA-256 wire digest)
├── class_uid         : int32 (OCSF Class, e.g. 4001, 2001, 3002)
├── category_name     : string (OCSF Category)
├── activity_name     : string (Normalized activity)
├── severity_id       : int32 (OCSF Severity 1-6)
├── severity          : string (Informational, Low, Medium, High, Critical)
├── src_endpoint_ip   : string (nullable)
├── src_endpoint_port : int32 (nullable)
├── dst_endpoint_ip   : string (nullable)
├── dst_endpoint_port : int32 (nullable)
├── protocol_name     : string (nullable)
├── user_name         : string (nullable)
└── unmapped_json     : string (JSON string of vendor-specific passthrough attributes)

Footer Metadata:
- ulpf_schema_version : "1.1.0-ocsf-contract"
- ocsf_version        : "1.1.0"
```

---

## 3. Mock Receiver Verification

Verified in automated test suite `tests/test_integration_sinks.py`:
- Parquet readback confirms byte columns and footer schema metadata version.
- Mock HTTP server verifies Splunk HEC auth headers and batch payload formatting.
- Mock HTTP server verifies Elastic `/_bulk` headers and action lines.
- Mock UDP socket verifies Syslog CEF/LEEF forwarding.
