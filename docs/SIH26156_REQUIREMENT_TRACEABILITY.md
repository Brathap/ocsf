# SIH 26156 — Official Requirement Traceability Matrix

**Competition:** Smart India Hackathon 2026  
**Problem Statement:** SIH 26156 — Universal Log Pre-processing Framework (ULPF)  
**Organization:** National Technical Research Organisation (NTRO)  
**Verification Date:** 2026-10-05  

---

| SIH Req ID | Official Requirement Description | ULPF Architectural Implementation | Source File(s) | Verification Test(s) | Live Demonstration | Status |
| :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| **(a)** | **Lossless raw event data preservation** | Wire bytes preserved via Base64 encoding + deterministic SHA-256 hash prior to parsing. Round-trip byte-for-byte exactness verification. | `backend/reconstruction_verifier.py`<br>`backend/storage_engine.py` | `tests/test_reconstruction.py`<br>`tests/test_ulpf_suite.py::test_a` | `evaluate.py` (Item 1 & 2)<br>Forensic Inspector Tab in UI | **PASS** |
| **(b)** | **Attribute extraction from diverse formats** | Fast Path parsing with declarative YAML source packs (Cisco ASA, Palo Alto, Linux SSH, CEF, Syslog RFC5424/3164, JSON, CSV). | `backend/source_packs/registry.py`<br>`sources/vendors/*.yaml` | `tests/test_source_packs_and_intelligence.py`<br>`tests/test_ip_extraction.py` | `python ulpf.py demo` (Scene A)<br>`python ulpf.py benchmark` | **PASS** |
| **(c)** | **Normalization into common taxonomy** | Pinned OCSF v1.1.0 specification (Classes 4001, 3002, 2001, 1001) mapping network, auth, finding, and file activities. | `backend/source_packs/registry.py`<br>`docs/schema/OCSF_VERSION.md` | `tests/test_ulpf_suite.py::test_b_c`<br>`evaluate.py` (Item 8) | `python ulpf.py demo` (Scene A)<br>OCSF JSON Viewer in UI | **PASS** |
| **(d)** | **Traceability between normalized & original events** | Granular field-level lineage linking OCSF attributes to exact start/end byte offsets and raw tokens in wire payload. | `backend/lineage_engine.py` | `tests/test_source_packs_and_intelligence.py`<br>`evaluate.py` (Item 9) | `python ulpf.py demo` (Scene D)<br>Forensic Byte-Span Inspector in UI | **PASS** |
| **(e)** | **Plug-and-play onboarding of new log sources** | Adaptive Source Intelligence: Format Fingerprinter, Drain-style Template Clusterer, and Field Inferencer. | `backend/unknown_engine/intelligence.py`<br>`backend/source_packs/registry.py` | `tests/test_source_packs_and_intelligence.py`<br>`tests/test_onboarding_consensus.py` | `python ulpf.py analyze`<br>`python ulpf.py generate-pack` | **PASS** |
| **(f)** | **Unified enterprise visibility** | Real-time SOC dashboard displaying live stream, throughput velocity, categorization, and audit log. | `frontend/src/components/LiveStream.tsx`<br>`frontend/src/components/HeroMetrics.tsx` | `npm --prefix frontend run build`<br>`tests/test_ulpf_suite.py::test_f` | Live browser interface on port 3000 / 8000 | **PASS** |
| **(g)** | **Efficient SIEM & Data Lake integration** | Streamlined endpoints (SSE `/api/stream`, JSONL rotating file, and Parquet data lake readiness). | `backend/main.py`<br>`backend/storage_engine.py` | `tests/test_deep_resilience.py`<br>`tests/test_storage_architecture.py` | `evaluate.py` (Item 12, Replay)<br>JSONL archive in `storage/` | **PASS** |
| **(h)** | **AI/ML-ready analytics** | Strongly-typed, normalized OCSF JSONL outputs paired with offline threat intelligence IOC correlation. | `backend/threat_intel_manager.py`<br>`backend/threat_intel.csv` | `tests/test_threat_intel_update.py`<br>`tests/test_ulpf_suite.py::test_h` | Threat matrix badges and alert cards in UI | **PASS** |
| **(i)** | **Reduced parser development effort** | Offline candidate YAML source pack generator with automatic hot reload and rollback safety. | `backend/unknown_engine/intelligence.py`<br>`backend/source_packs/registry.py` | `tests/test_source_packs_and_intelligence.py`<br>`evaluate.py` (Item 6 & 7) | `python ulpf.py demo` (Scene B & C) | **PASS** |
| **(j)** | **Air-gapped network deployable** | Strict egress socket interceptor, fail-closed self-tests, zero cloud AI calls, zero external telemetry. | `backend/egress_enforcement.py`<br>`scripts/verify_airgap.py` | `tests/test_egress_enforcement.py`<br>`evaluate.py` (Item 13) | `python ulpf.py verify-airgap`<br>Air-Gap Provenance Screen in UI | **PASS** |
| **(k)** | **Container packaged** | Multi-stage Dockerfile and docker-compose deployment with isolated bridge networking. | `Dockerfile`<br>`docker-compose.yml` | `docker compose config` validation | `docker compose up --build` | **PASS** |

---

## Conclusion
All 11 official requirements (a through k) are satisfied with concrete implementations and passing tests.
