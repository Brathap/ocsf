#!/usr/bin/env bash
# ==============================================================================
# scripts/sysctl_tune.sh - Sovereign OS Kernel Network Hardening (SIH 26156)
# ==============================================================================
# Enforces enterprise network buffer tuning and zero-packet-drop integrity:
# 1. Configures net.core.rmem_max=26214400 (25MB socket receive buffer)
# 2. Configures net.core.wmem_max=26214400
# 3. Documents TCP/TLS 5425 over raw UDP 514 for zero-packet-drop integrity.
# ==============================================================================

set -euo pipefail

echo "=============================================================================="
echo "          ULPF ENTERPRISE KERNEL NETWORK & BUFFER TUNING (SYSCTL)             "
echo "=============================================================================="
echo "Target Parameter : net.core.rmem_max = 26214400 (25 MB socket receive buffer)"
echo "Target Parameter : net.core.wmem_max = 26214400 (25 MB socket send buffer)"
echo "Security Posture : Mandates TCP/TLS 5425 over raw UDP 514 for zero-drop integrity"
echo "------------------------------------------------------------------------------"

# Apply sysctl parameters if root or sudo available
if [ "$(id -u)" -eq 0 ]; then
    echo "[*] Applying kernel socket memory buffer parameters via sysctl..."
    sysctl -w net.core.rmem_max=26214400
    sysctl -w net.core.wmem_max=26214400
    sysctl -w net.core.rmem_default=26214400
    sysctl -w net.core.netdev_max_backlog=10000
    echo "[✓] Successfully tuned kernel socket buffers."
else
    echo "[*] Non-root execution. Displaying sysctl tuning configuration:"
    echo "    sudo sysctl -w net.core.rmem_max=26214400"
    echo "    sudo sysctl -w net.core.wmem_max=26214400"
    echo "    sudo sysctl -w net.core.netdev_max_backlog=10000"
fi

echo ""
echo "=============================================================================="
echo "   ENTERPRISE NETWORK PROTOCOL ARCHITECTURE: TCP/TLS 5425 vs RAW UDP 514      "
echo "=============================================================================="
echo "• UDP 514 (Legacy Syslog RFC 3164/5424):"
echo "  - Vulnerability: Unreliable fire-and-forget datagram delivery."
echo "  - Vulnerability: Trivial Source IP spoofing without cryptographic authenticity."
echo "  - Vulnerability: Kernel buffer drops during traffic spikes (burst > rmem_max)."
echo ""
echo "• TCP/TLS 5425 (RFC 5425 Secure Syslog with mTLS):"
echo "  - Zero Packet Drop: TCP windowing and flow control guarantee lossless delivery."
echo "  - Anti-Spoofing: Mandates x.509 client certificate mutual authentication (mTLS)."
echo "  - Air-Gap Privacy: Encrypted in-flight payload prevents passive perimeter eavesdropping."
echo "=============================================================================="
