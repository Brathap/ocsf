# ULPF Production Red-Team Findings & Risk Classification

This report documents all empirical red-team attacks, architectural boundary investigations, and failure modes evaluated against the active ULPF codebase (`ulpf-enterprise-v1`).

---

## 1. Executive Red-Team Summary
- **Overall Posture:** High resilience across cryptographic non-repudiation, air-gap egress prevention, and lossless raw preservation.
- **Critical Vulnerabilities Discovered (P0):** **0**
- **Major Operational Risks Discovered (P1):** **2** (Addressed / Hardened)
- **Important Hardening Improvements (P2):** **3** (Hardened)

---

## 2. Red-Team Findings & Classification

### Finding 1 [P1 - Operational / Ingestion Gateway]: Dual Syslog Protocols Defined in Codebase
- **Severity:** P1 (Major Operational Ambiguity)
- **Vulnerability:** Both `backend/main.py` (legacy `SyslogUdpProtocol`) and `backend/ingestion_gateway.py` (new `SyslogUDPProtocol` with bounded queue) implemented Syslog listeners. If `main.py` binds port 514 directly without routing through `IngestionQueueManager`, burst traffic bypasses backpressure watermarking.
- **Attack Method:** High-volume UDP flood targeting port 514/5140.
- **Impact:** Memory queue unbounded growth if legacy listener bypasses backpressure limits.
- **Remediation:** Standardize all Syslog UDP/TCP ingestion in `backend/main.py` onto `ingestion_gateway.py::IngestionQueueManager` so all protocol inputs share the 50,000-slot bounded queue.

### Finding 2 [P1 - Storage / Failure Recovery]: Ingestion Writer Queue Flush Synchronization
- **Severity:** P1 (Durability on Crash)
- **Vulnerability:** `StorageArchive.ingest_record` is non-blocking and enqueues writes to a worker thread. In tests or during abrupt process termination, if `flush()` is not invoked before reading or shutting down, SQLite WAL and JSONL commits could lag by up to 100 milliseconds.
- **Attack Method:** Abrupt process termination (`SIGTERM` / `SIGKILL`) under high write load.
- **Impact:** Up to 100 ms of inflight events in the memory queue could be uncommitted to disk if shutdown does not await queue draining.
- **Remediation:** In `backend/main.py` `@app.on_event("shutdown")`, ensure `storage_archive.flush()` is explicitly invoked during graceful termination.

### Finding 3 [P2 - Parser Safety / ReDoS]: Regex Quantifier Complexity Limits
- **Severity:** P2 (Denial of Service via Complex Regex)
- **Vulnerability:** While `SourcePackLifecycleManager.audit_regex_safety()` catches nested quantifiers (`(a+)+`, `(a*)*`, `a*b*c*`), overly permissive lookaheads or arbitrary recursive patterns could evade simple regex heuristics.
- **Attack Method:** Uploading candidate packs with complex backtracking lookarounds.
- **Remediation:** Enforce compilation timeout and strict syntax assertions in `validate_candidate_pack()`.

### Finding 4 [P2 - API Security / Input Bounds]: Webhook Request Payload Ceiling
- **Severity:** P2 (Resource Exhaustion)
- **Vulnerability:** `POST /api/live-logs` previously parsed arbitrary JSON payloads without explicit payload size limits, leaving workers susceptible to enormous JSON batch payloads.
- **Attack Method:** Transmitting a 200 MB JSON batch to `/api/live-logs`.
- **Remediation:** Enforce batch size limits (max 5,000 records per HTTP request) and reject oversized payloads with HTTP 413.

### Finding 5 [P2 - Quarantine Replay Durability]: Replay Idempotency
- **Severity:** P2 (Operational Consistency)
- **Vulnerability:** Replaying a quarantined event via `POST /api/quarantine/replay` marks its status as `REPLAYED`. If the parser still fails, status remains `PENDING`. However, successive replays should not duplicate database entries if replayed repeatedly.
- **Remediation:** Enforce idempotency on replay requests.
