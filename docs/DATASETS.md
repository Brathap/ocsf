# Real-World Log Datasets & Empirical Coverage Report
**Document:** `docs/DATASETS.md`  
**Execution Timestamp:** 2026-10-06  
**Auditor:** AegisGuard-ULPF Empirical Verification Pipeline  
**Execution Command:** `python3 tools/measure_coverage.py`

---

## 1. Methodology & Data Provenance

All evaluation metrics in this report are measured directly from authentic public production log corpora downloaded via `python3 tools/fetch_datasets.py` into `realdata/` (strictly gitignored, never redistributed or checked into version control).

### Datasets Tested:
1. **Loghub OpenSSH 2k**: 2,000 real authentication events from a live production server.
2. **Loghub Linux Syslog 2k**: 2,000 genuine Linux system daemon, auth, su, logrotate, and cron logs.
3. **Loghub Apache Web 2k**: 2,000 Apache web server error and access logs.
4. **Loghub Proxifier 2k**: 2,000 client proxy tunnel connection events.
5. **Loghub HDFS 2k**: 2,000 Hadoop distributed file system cluster events.

> **Zero Records Lost Guarantee:**  
> Unparsed logs are **never discarded**. When an incoming log line does not match any registered vendor pack signature, it is preserved losslessly in the Base64 wire archive alongside its SHA-256 digest, and emitted as an OCSF v1.1.0 generic unparsed envelope (`class_uid: 6001`) with complete unmapped passthrough.

---

## 2. Empirical Measured Results

The following figures were generated from an automated run of `python3 tools/measure_coverage.py`:

| Corpus Name | Total Records | Full Parsed % | Partial % | Unparsed % | Unparsed Preserved | Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Loghub OpenSSH 2k** | 2,000 | **68.40%** (1,368) | **31.60%** (632) | **0.00%** (0) | **YES (2,000 / 2,000)** | **100% PRESERVED** |
| **Loghub Linux Syslog 2k** | 2,000 | **24.45%** (489) | **24.15%** (483) | **51.40%** (1,028) | **YES (2,000 / 2,000)** | **100% PRESERVED** |
| **Loghub Apache Web 2k** | 2,000 | **100.00%** (2,000) | **0.00%** (0) | **0.00%** (0) | **YES (2,000 / 2,000)** | **100% PRESERVED** |
| **Loghub Proxifier 2k** | 2,000 | **60.70%** (1,214) | **0.00%** (0) | **39.30%** (786) | **YES (2,000 / 2,000)** | **100% PRESERVED** |
| **Loghub HDFS 2k** | 2,000 | **100.00%** (2,000) | **0.00%** (0) | **0.00%** (0) | **YES (2,000 / 2,000)** | **100% PRESERVED** |
| **AGGREGATE TOTAL** | **10,000** | **70.71%** (7,071) | **11.15%** (1,115) | **18.14%** (1,814) | **YES (10,000 / 10,000)** | **0 RECORDS LOST** |

*Overall Emitted OCSF Rate:* **100.0%** (10,000 / 10,000 records emitted; 0 records lost).

---

## 3. Top Miss Patterns & Root Causes

### 1. OpenSSH Partial Extractions (31.60% / 632 records)
- **Top Patterns:** `pam_unix(sshd:auth): check pass; user unknown`, `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=...`
- **Root Cause:** Internal PAM authentication status transitions that do not carry a client IP or username in standard OpenSSH CLI format.
- **Handling:** Mapped to OCSF Class 3002 with status detail preserved.

### 2. Linux Syslog Unparsed (51.40% / 1,028 records)
- **Top Patterns:** Standard kernel syslog prefixes without registered daemon signatures (`kernel: [   0.000000] BIOS-e820`, `logrotate: ALERT exited abnormally`).
- **Root Cause:** Raw kernel memory maps, device initialization, and miscellaneous system daemons.
- **Handling:** Losslessly preserved in Base64 wire vault and emitted as unparsed OCSF envelopes.

### 3. Proxifier Unparsed (39.30% / 786 records)
- **Top Patterns:** `svchost.exe *64 - proxy:5070 close, ...`, `QQ.exe - tcpconn error : A connection request was canceled`.
- **Root Cause:** 64-bit architecture asterisks (`*64`) and multi-clause TCP error strings diverging from the standard tunnel open/close syntax.
- **Handling:** Losslessly preserved with SHA-256 wire digest.
