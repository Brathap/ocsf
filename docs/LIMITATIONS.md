# ULPF SIH26156 — Known Limitations & System Boundaries

**Project:** Universal Log Pre-processing Framework (ULPF)  
**Governance:** SIH 26156 / NTRO  
**Date:** 2026-10-05  

---

## 1. Operating Boundaries & Invariants

To remain lightweight, air-gapped, and high-performance, ULPF implements deliberate architectural boundaries:

1. **Deterministic Inference vs. Generative Hallucination:**
   - ULPF does not use deep generative neural networks (LLMs) for runtime parsing. Parser proposal is deterministic and based on structural tokenization and regular expressions.
   - Ambiguous or low-confidence extractions are quarantined rather than guessed.

2. **Cross-Platform Verification Boundary:**
   - **Tested Environments:** Linux (Arch Linux 64-bit kernel 7.1.6-zen, Ubuntu/Debian containers).
   - **Expected Compatible:** Windows (PowerShell/WSL2) and macOS via standard Python runtime.
   - *Limitation:* Linux kernel-level firewall generation (`iptables`/`nftables`) requires Linux network namespaces.

3. **Storage Scaling Boundary:**
   - The standalone prototype uses SQLite in Write-Ahead Logging (WAL) mode alongside append-only JSONL files.
   - *Capacity:* Optimal for edge nodes and appliances processing up to ~10–20 million logs locally per day. Enterprise multi-terabyte deployments should forward normalized outputs to Kafka, Parquet S3/MinIO, or distributed cold storage.

4. **Lineage Precision for Non-Substring Transformations:**
   - Lineage byte spans `[start, end]` are exact when the extracted value is a substring of the raw wire payload.
   - For calculated or derived values (such as mapped integer severity IDs or translated timestamps), the lineage engine records the raw source token from which the calculation was derived rather than a direct string slice.

5. **Multi-Line Log Handling:**
   - Current stream processing assumes newline-delimited events (JSON, Syslog, CEF, CSV). Multi-line stack traces are handled when encapsulated within standard quotes or framed by syslog RFC 5424 octet counting.
