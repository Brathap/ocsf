#!/usr/bin/env bash
# ==============================================================================
# AegisGuard-ULPF — Official SIH 26156 Interactive Live Demo Launcher
# ==============================================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "    🛡️  AEGISGUARD-ULPF : LIVE DEMO LAUNCHER (SIH 26156 - NTRO)       "
echo "    Universal Sovereign Log Pre-processing & Provenance Framework     "
echo "======================================================================"
echo " Mode: Air-Gapped / Privacy-Preserving / OCSF v1.1.0 Strict"
echo ""

cleanup() {
    echo ""
    echo "[AegisGuard-ULPF] Halting demo background tasks..."
    kill $(jobs -p) 2>/dev/null || true
    echo "[AegisGuard-ULPF] Clean shutdown completed."
}
trap cleanup EXIT INT TERM

# 1. Pre-flight Air-Gap & Environment Audit
echo "[1/4] Running Pre-Flight Air-Gap & Socket Egress Audit..."
python3 scripts/verify_airgap.py >/dev/null 2>&1 && echo "  -> [OK] Fail-closed socket interception active. 0 external WAN calls."

# 2. Launch FastAPI Backend
echo "[2/4] Starting AegisGuard-ULPF Core Engine on port 8000..."
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --log-level warning &
BACKEND_PID=$!
sleep 2

# 3. Launch Frontend SOC Dashboard
echo "[3/4] Starting React SOC Cyber Console on port 5173..."
(cd frontend && npm run dev -- --host --clearScreen false) >/dev/null 2>&1 &
FRONTEND_PID=$!
sleep 2

# 4. Launch Heterogeneous Real-Time Stream Simulator
echo "[4/4] Starting Multi-Source Telemetry Simulator (Cisco, CEF WAF, SSHD)..."
python3 backend/simulate_firehose.py &
SIM_PID=$!

echo ""
echo "======================================================================"
echo " 🚀 DEMO IS RUNNING & READY FOR JUDGES!"
echo "----------------------------------------------------------------------"
echo " 🌐 Web SOC Console: http://localhost:5173"
echo " 🔌 Swagger Docs:    http://localhost:8000/docs"
echo " 📡 Ingestion Port:  UDP 127.0.0.1:5140 (Syslog / Vector Fallback)"
echo ""
echo " 💡 JUDGE VERIFICATION COMMANDS (Try in another terminal):"
echo "    1. Ingest/Test:      python3 ulpf.py test"
echo "    2. Raw Preservation: python3 ulpf.py raw \"CEF:0|Imperva|WAF|14.0|SQLI|9|src=1.2.3.4\""
echo "    3. Merkle Proof:     python3 ulpf.py prove --index 1"
echo "    4. Profile Unknown:  python3 ulpf.py profile \"2026-10-05 GW01 evt=DROP ip=1.1.1.1\""
echo "    5. Air-Gap Audit:    python3 ulpf.py verify-airgap"
echo "----------------------------------------------------------------------"
echo " Press Ctrl+C to terminate all demo services."
echo "======================================================================"
echo ""

wait
