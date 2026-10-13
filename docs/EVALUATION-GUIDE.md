# ULPF Grand Jury Technical Evaluation Guide (SIH 26156)

> **Evaluator's Playbook: Six adversarial ways to inspect, attack, and mathematically verify ULPF in under 20 minutes.**  
> Designed for technical evaluators, red-team auditors, and skeptical judges with a live terminal.

---

## 0. Quick Sanity Check (1 Minute)

Run the full automated regression suite directly from repository root:
```bash
python3 -m pytest -v
```
**Expected**: 74 automated unit & integration tests pass in ~22 seconds.

---

## 1. Six Adversarial Tests to "Catch Us Out"

### Test 1: Active Socket Egress Interception (Fail-Closed Air-Gap Proof)
* **The Claim:** ULPF enforces strict air-gapped zero external egress at the socket syscall layer, blocking exfiltration attempts even if application code is backdoored.
* **The Attack Command:**
  ```bash
  python3 scripts/verify_airgap.py
  ```
* **What to Check:**
  - Probes attempted: 4 (DNS `google.com:53`, HTTP `1.1.1.1:80`, HTTPS `8.8.8.8:443`, Raw TCP `93.184.216.34:8080`).
  - Probes blocked: 4/4 with `PermissionError: [Errno 1] Operation not permitted (ULPF Air-Gap Active)`.
  - Loopback status: `127.0.0.1` remains active for local IPC.
  - Telemetry scan: 0 external cloud endpoints.

---

### Test 2: Cryptographic WORM Immutability & Duplicate ID Collision Rejection
* **The Claim:** SQLite storage engine enforces single-writer WAL mode, rejects record overwrites (`INSERT OR REPLACE` strictly forbidden), and logs collision tampering in an audit ledger.
* **The Attack Command:**
  ```bash
  python3 -m pytest tests/test_storage_architecture.py -k "collision" -v
  ```
* **Verify in Database:**
  ```bash
  sqlite3 storage/ulpf_analytics.db "SELECT action, event_id, timestamp FROM audit_log ORDER BY id DESC LIMIT 5;"
  ```
* **Expected Output:**
  - Tamper injection fails with collision rejection.
  - Audit table records `INSERT_COLLISION_REJECTED` with original record hash preserved.

---

### Test 3: RFC 6962 Merkle Tree Inclusion Proofs & Re-Seal Tamper Defense
* **The Claim:** Every archived security event is anchored in an RFC 6962 cryptographic Merkle Tree with domain-separated hashing (`0x00` leaf, `0x01` interior node) and Ed25519-signed checkpoints. Any record can be verified independently without system access using `verify_bundle.py`.
* **The Attack Command:**
  ```bash
  python3 scripts/tamper_demo.py
  ```
* **Independent Standalone Verification Command:**
  ```bash
  python3 verify_bundle.py /tmp/ulpf_evidence_bundle.json <enclave_pubkey_hex>
  ```
* **Expected Output:**
  - Genuine bundle verifies 100%.
  - Single-byte mutation output: `[TAMPER DETECTED] Record #0: SHA-256 mismatch!`.
  - Full tree re-seal attempt output: `[TAMPER DETECTED] Record #0: Claimed root diverges from signed enclave checkpoint`.


---

### Test 4: Indian Sovereign PII Redaction (Verhoeff & Luhn False-Positive Rejection)
* **The Claim:** Aadhaar numbers are verified via the dihedral group $D_5$ (Verhoeff algorithm) — not naive 12-digit regexes. False-positive numbers (e.g. 12-digit timestamps or order IDs) are never scrubbed. Income Tax PAN and Luhn IMEI are strictly validated.
* **The Attack Command:**
  ```bash
  python3 -m pytest tests/test_pii_coverage.py -v
  ```
* **Manual Verification in Terminal:**
  ```bash
  python3 -c "
  from backend.pii_redactor import redact_pii
  # Valid Aadhaar (passes Verhoeff D5): 982345129088
  # Invalid 12-digit timestamp: 172734567890
  sample = 'user kyc=982345129088 order_ts=172734567890 pan=ABCDE1234F'
  sanitized, types = redact_pii(sample)
  print('Sanitized:', sanitized)
  print('Redacted Types:', types)
  assert '172734567890' in sanitized, 'Timestamp must NOT be scrubbed!'
  assert '982345129088' not in sanitized, 'Aadhaar MUST be scrubbed!'
  assert 'ABCDE1234F' not in sanitized, 'PAN MUST be scrubbed!'
  "
  ```
* **Expected Output:**
  - Aadhaar and PAN replaced with tokens; timestamp preserved untouched.

---

### Test 5: ReDoS Catastrophic Backtracking Attack
* **The Claim:** Custom or candidate Source Pack regexes undergo mandatory ReDoS static heuristic checking and execution timeout boundaries, preventing exponential backtracking Denial-of-Service.
* **The Attack Command:**
  ```bash
  python3 -c "
  from backend.source_packs.lifecycle import SourcePackLifecycleManager, SourcePackSecurityError
  evil_patterns = [r'(a+)+$', r'(a*)*$', r'([a-z]+*)*']
  for pat in evil_patterns:
      try:
          SourcePackLifecycleManager.audit_regex_safety(pat)
          print(f'Pattern {pat}: UNEXPECTED PASS')
      except SourcePackSecurityError as e:
          print(f'Pattern {pat} -> REJECTED: {e}')
  "
  ```
* **Expected Output:**
  - All catastrophic nested quantifier patterns raise `SourcePackSecurityError` and are rejected pre-compilation.

---

### Test 6: Byte-Level Reconstruction Gate & Exact Offset Lineage
* **The Claim:** Normalization guarantees bit-exact raw-wire character offset lineage. Candidate packs cannot alter wire bytes without tripping the reconstruction gate.
* **The Attack Command:**
  ```bash
  python3 -m pytest tests/test_reconstruction.py -v
  ```
* **Manual API Rejection Test:**
  ```bash
  python3 -c "
  from backend.reconstruction_verifier import verify_reconstruction
  raw = b'<164>Oct 24 ciscoasa: Denied tcp src 198.51.100.23/50901 dst 10.0.0.1/80'
  parsed = {'prival': '164', 'host': 'ciscoasa', 'src': '198.51.100.23/50901', 'dst': '10.0.0.1/80'}
  bad_rule = {'reverse_template': '<{prival}> {host}: Denied tcp src {src} dst {dst}'}
  res = verify_reconstruction(raw, parsed, bad_rule)
  print('Verdict:', res['verdict'])
  print('Diff Details:', res['diff'])
  assert res['verdict'] == 'fail'
  "
  ```
* **Expected Output:**
  - `Verdict: fail` with explicit byte-level divergence offsets.

---

## 2. Replay Genuine Captured Perimeter Telemetry

Replay genuine captured honeynet and firewall traces (Honeynet SotM 34, Cisco ASA, Linux UFW, Imperva CEF):
```bash
python3 backend/replay_corpus.py --port 5140 --rate 10
```
Inspect real-time ingestion in the SOC Console at [http://localhost:5173](http://localhost:5173).
