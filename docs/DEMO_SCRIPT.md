# AegisGuard-ULPF — Official 2-Minute SIH Demo Video Script
**Target Duration:** Exactly 120 Seconds (2 Minutes)  
**Presenter:** Security Architect / Team Lead  
**Tone:** Calm, authoritative, technical, evidence-first.

---

### [0:00 – 0:20] SCENE 1: THE PROBLEM & SOVEREIGN TELEMETRY CHAOS
* **Visual:** Split screen showing messy, malformed vendor logs (Cisco ASA, Imperva CEF, Linux SSHD, Palo Alto) pouring into a terminal alongside an alert dashboard.
* **On-Screen Text:** "SIH 26156: Universal Log Pre-processing Framework (NTRO)"
* **Narration:**
  > "In high-stakes national cyber defense, security operations centers ingest billions of logs from dozens of proprietary hardware vendors. Each uses different schemas, timestamps, and formats. Analysts spend 60% of their time writing brittle regexes, while unverified parsing destroys evidentiary chain-of-custody.
  > This is **AegisGuard-ULPF** — an air-gapped, sovereign telemetry framework that transforms vendor chaos into strictly validated OCSF records with bit-exact byte lineage and mathematical proof-of-custody."

---

### [0:20 – 0:50] SCENE 2: LIVE MULTI-SOURCE INGESTION & FORENSIC PROVENANCE
* **Visual:** Terminal runs `./start_demo.sh`. Browser switches to React SOC Cyber Console (`http://localhost:5173`). Live logs stream in across Cisco ASA, ArcSight CEF, and Linux SSHD. Presenter clicks on a Cisco ASA event to open the Log Drawer.
* **UI Actions:**
  1. Highlight **Raw Wire Payload** with SHA-256 digest `1a90c0aa...`.
  2. Switch to **OCSF Normalized View** showing Class `4001: Network Activity`.
  3. Switch to **Forensic Lineage Tab** showing exact character spans `[63:75]` for source IP `198.51.100.4`.
* **Narration:**
  > "Here, our engine processes multiple live perimeter streams simultaneously. Look closely at this Cisco ASA firewall connection event:
  > First, the raw wire payload was preserved in base64 with a SHA-256 digest before any transformation.
  > Second, it's normalized into OCSF v1.1.0 Class 4001.
  > Third, our lineage engine maintains exact character span pointers linking every OCSF field directly back to its original bytes on the wire. No hallucination, no offset drift."

---

### [0:50 – 1:20] SCENE 3: DETERMINISTIC ONBOARDING OF UNKNOWN SOURCES
* **Visual:** Presenter switches to terminal and blasts an unknown proprietary appliance log:  
  `2026-10-05 GW01 evt=PACKET_DROP client_ip=203.0.113.88 srv_ip=198.51.100.4 proto=TCP`  
  Console flags it as `UNKNOWN / QUARANTINED`.
* **CLI Action:**
  ```bash
  python3 ulpf.py profile "2026-10-05 GW01 evt=PACKET_DROP client_ip=203.0.113.88 srv_ip=198.51.100.4 proto=TCP"
  python3 ulpf.py draft --vendor NeoDefense --product Gateway "..."
  ```
* **Narration:**
  > "When an unknown vendor device appears on the network, traditional pipelines fail silently or drop packets.
  > AegisGuard-ULPF routes the log to quarantine and engages our offline Adaptive Intelligence engine.
  > In one command — `ulpf profile` — it extracts delimiter entropy, clusters the grammar template, and infers OCSF fields with 95% confidence.
  > `ulpf draft` generates a candidate declarative Source Pack. The SOC operator reviews and promotes it with zero downtime. Subsequent events immediately hit the fast-path."

---

### [1:20 – 1:45] SCENE 4: RFC 6962 MERKLE INTEGRITY & TAMPER PROOFS
* **Visual:** Presenter clicks **Verify In Ledger** in the UI, then demonstrates terminal proof verification:
* **CLI Action:**
  ```bash
  python3 scripts/tamper_demo.py
  python3 verify_bundle.py /tmp/ulpf_evidence_bundle.json <enclave_pubkey>
  ```
  Mutating 1 byte in the leaf payload causes the verification script to output `[TAMPER DETECTED] SHA-256 mismatch`. Re-sealing the tree is caught by the externally held Ed25519 enclave checkpoint.
* **Narration:**
  > "To guarantee evidentiary chain-of-custody for judicial forensics and CERT-In compliance, every batch of logs is anchored into an RFC 6962 cryptographic Merkle tree with Ed25519-signed checkpoints.
  > Any auditor can independently verify an evidence bundle with our standalone script with zero access to the system. If an attacker tampers with even a single byte or attempts a full re-seal attack, it is mathematically rejected."

---

### [1:45 – 2:00] SCENE 5: AIR-GAP SOVEREIGNTY & STATUTORY COMPLIANCE
* **Visual:** Terminal runs `python3 scripts/verify_airgap.py` showing 4/4 external probes blocked with `EPERM`. Shows CERT-In 6-Hour export dossier download and Verhoeff-redacted Aadhaar tokens.
* **On-Screen Text:** "AegisGuard-ULPF: 100% Sovereign. Air-Gapped. NTRO SIH 26156 Ready."
* **Narration:**
  > "Finally, AegisGuard-ULPF operates under strict air-gap constraints. Outbound sockets are hard-blocked at the kernel interface. Integrated Verhoeff checksums redact Indian Aadhaar numbers without false-positive timestamp corruption, and CERT-In 6-hour incident dossiers export automatically.
  > AegisGuard-ULPF: Different logs. One security language. Every transformation accounted for."
