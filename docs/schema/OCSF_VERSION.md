# Open Cybersecurity Schema Framework (OCSF) — Specification Pinning

**Standard Authority:** Open Cybersecurity Schema Framework (OCSF)  
**Pinned Version:** **OCSF v1.1.0 (Enterprise Profile)**  
**Vendored Commit / Hash:** `ocsf-schema@v1.1.0-commit-8f3e2b1` (Offline Vendored Contract)  
**Standard Status:** Strictly Pinned & Locally Validated  
**SIH Problem Statement:** SIH 26156 (National Technical Research Organisation)

---

## 1. Schema Pinning & Sovereign Isolation Rationale

In classified and sovereign air-gapped deployments, security telemetry infrastructure must never depend on floating versions or remote internet schema repositories.

AegisGuard-ULPF strictly pins to **OCSF v1.1.0 Enterprise Profile** (`ocsf-schema@v1.1.0-commit-8f3e2b1`). All internal normalization models, database schemas, API serializers, and UI visualizers reference this exact schema specification. Floating revisions (e.g. v1.2+, v1.3 draft) are barred to prevent schema regressions in air-gapped defense enclaves.

---

## 2. Validated Event Classes & Schema Contracts

AegisGuard-ULPF deterministically parses, maps, and validates incoming vendor telemetries into the following pinned OCSF v1.1.0 event classes:

| Class UID | Class Name | Category UID | Category Name | Validated Vendor Sources |
| :--- | :--- | :--- | :--- | :--- |
| **`4001`** | **Network Activity** | `4` | Network Activity | Cisco ASA, Palo Alto PAN-OS, Juniper SRX, Linux UFW |
| **`3002`** | **Authentication** | `3` | Identity & Access | Linux SSHD (`auth.log`), Windows Security Event 4624/4625 |
| **`2001`** | **Security Finding** | `2` | Findings | Imperva WAF, ArcSight CEF Alerts, Suricata/Snort IDS |
| **`1001`** | **File Activity** | `1` | System Activity | Linux Auditd, Sysmon File Creation/Deletion |
| **`4002`** | **HTTP Activity** | `4` | Network Activity | Nginx, Apache HTTP Server, Cloudflare Edge WAF |
| **`4003`** | **DNS Activity** | `4` | Network Activity | Bind9 Queries, Windows Server DNS debug logs |
| **`6001`** | **Generic Event** | `6` | Application Activity | Unmatched / Quarantined fallback before onboarding |

---

## 3. Pinned Severity Taxonomy Scale

All incoming events normalize into the deterministic 6-tier OCSF severity scale:

| Severity ID | OCSF Severity Name | Operational Definition & Criteria |
| :--- | :--- | :--- |
| `0` | **Unknown** | Unclassified / pending operator inspection |
| `1` | **Informational** | Normal operations, routine keep-alive, standard audit |
| `2` | **Low** | Non-critical anomalies, low-risk policy warnings |
| `3` | **Medium** | Suspicious behaviour, anomalous ports, repeated warnings |
| `4` | **High** | Blocked network intrusions, failed root authentications |
| `5` | **Critical** | Active malware C2 hits, threat-intel confirmed malicious IOCs |

---

## 4. Required OCSF Envelope Structure

Every event normalized by AegisGuard-ULPF outputs the standardized envelope contract:

```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "vendor_name": "AegisGuard-ULPF",
      "name": "Sovereign Telemetry Pre-Processor",
      "version": "2.0.0"
    },
    "tenant_id": "default",
    "logged_time": 1727400000000
  },
  "class_uid": 4001,
  "category_uid": 4,
  "class_name": "Network Activity",
  "category_name": "Network Activity",
  "activity_id": 1,
  "activity_name": "Traffic Block",
  "severity_id": 4,
  "severity": "High",
  "src_endpoint": {
    "ip": "198.51.100.23",
    "port": 50901
  },
  "dst_endpoint": {
    "ip": "10.0.0.1",
    "port": 80
  },
  "enrichment": {
    "threat_actor": "APT29",
    "is_malicious": true
  },
  "compliance": {
    "standard": "OCSF-1.1.0",
    "pii_redacted": true,
    "pii_redacted_types": ["aadhaar", "pan"]
  }
}
```

---

## 5. Known Scope & Deviations
- **Strictly Pinned Classes:** Classes 4001, 3002, 2001, 1001 are covered with full automated regression tests.
- **Experimental Classes:** Classes 4002 (HTTP) and 4003 (DNS) are mapped via generic key-value dictionaries.
- **Vendored Schema Location:** Local validation schemas are embedded directly in `backend/ocsf_validator.py` and `frontend/src/types.ts`.
