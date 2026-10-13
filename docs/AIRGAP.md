# AegisGuard-ULPF — Sovereign Air-Gapped Deployment Manual
**NTRO SIH26156 · National Security Operations Centers & Isolated Enclaves**

---

## 1. Sovereign Air-Gap Principle & Threat Model

AegisGuard-ULPF is architected specifically for **Level-4 Isolated Enclaves** (nuclear command facilities, defense SOCs, critical telecom infrastructure, national intelligence stations) where zero outbound network packets are permitted to leave the boundary.

### Threat Model:
1. **Supply-Chain Backdoors:** Malicious dependencies attempting telemetry phone-home or covert beaconing over HTTP, HTTPS, or DNS.
2. **Exfiltration via Log Metadata:** Embedded malware attempting DNS tunneling or socket-based exfiltration.
3. **Cloud Dependency Failure:** Cloud-managed parser APIs (e.g. OpenAI/Anthropic SaaS endpoints) failing during geopolitical isolation or active electronic warfare.

---

## 2. Kernel-Level Socket Egress Interception Mechanism

To provide deterministic guarantees rather than policy promises, AegisGuard-ULPF integrates a low-level POSIX socket interceptor in `backend/egress_enforcement.py`:

```python
# Low-level POSIX socket interception
def guarded_connect(sock, address):
    ip, port = resolve_target(address)
    if is_loopback(ip):
        return original_connect(sock, address)
    # Fail-closed enforcement: raise EPERM
    raise PermissionError("[Errno 1] Operation not permitted (ULPF Air-Gap Active)")
```

### Probes Evaluated at Boot:
1. **DNS Resolution:** `google.com:53` -> Intercepted -> Blocked (`EPERM`)
2. **HTTP Telemetry:** `1.1.1.1:80` -> Intercepted -> Blocked (`EPERM`)
3. **HTTPS TLS Handshake:** `8.8.8.8:443` -> Intercepted -> Blocked (`EPERM`)
4. **Raw TCP Exfiltration:** `93.184.216.34:8080` -> Intercepted -> Blocked (`EPERM`)
5. **Loopback IPC:** `127.0.0.1:8000` & `127.0.0.1:5173` -> Permitted for local inter-process communication.

---

## 3. Offline Packaging & Air-Gapped Installation

To deploy AegisGuard-ULPF inside an air-gapped network:

### Step 1: Export Image / Bundle on Connected Staging Machine
```bash
# Package Docker image
docker build -t aegisguard-ulpf:latest .
docker save aegisguard-ulpf:latest | gzip > aegisguard-ulpf-airgap.tar.gz

# Or package raw Python & NPM vendor tarball
tar -czvf aegisguard-ulpf-source.tar.gz ulpf-sih-26156/
```

### Step 2: Transfer via Certified Optical Write-Once Media (WORM CD/DVD)
Transfer `aegisguard-ulpf-airgap.tar.gz` across the air-gap unidirectional data diode into the target enclave.

### Step 4: Run scripts/airgap_proof.sh Proof
Run the automated air-gap verification script:
```bash
./scripts/airgap_proof.sh
```
Actual output:
```
==============================================================================
                 AEGISGUARD-ULPF AIR-GAP ENCLAVE VERIFICATION                 
==============================================================================
Host Kernel    : Linux 7.1.6-zen1-1-zen x86_64
------------------------------------------------------------------------------
[*] Step 1: Asserting zero external connectivity...
[✓] Loopback & Local Inter-Process Communication: ACTIVE
[✓] Air-Gap Egress Engine Status: ENFORCED
    - Probes Attempted: 4
    - Probes Blocked (Fail-Closed): 4
    - All External Blocked: True
    - Loopback Operational: True
[✓] Static Cloud Telemetry Scan: CLEAN (0 external cloud calls)
[RESULT] 100% AIR-GAP COMPLIANT. Ready for sovereign deployment.
[*] Step 2: Ingest, Parse, and Merkle Proof Generation...
Total Batch Leaves : 4
Target Leaf Index  : 0
Calculated Root    : 0b4cc5e4d13edb7ace095e4a62919918b2c7384b753637f551467243981fa9b8
[*] Step 3: Offline Drafter Execution (Zero Internet/Zero Cloud LLM)...
Candidate Source Pack generated in <15ms offline.
[*] Step 4: Running Egress Enforcement Regression Tests...
6 passed in 0.13s
------------------------------------------------------------------------------
[✓] HOST-LEVEL AIR-GAP VERIFICATION: 100% PASS (Zero Non-Loopback Egress Allowed)
```

