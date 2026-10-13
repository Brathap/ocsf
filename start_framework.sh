#!/usr/bin/env bash
# ==============================================================================
# Universal Log Pre-processing Framework (ULPF) - SIH 26156
# Autonomous Orchestration Launcher (FastAPI + React Vite + UDP Firehose + Vector)
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "    🚀 STARTING ULPF ENTERPRISE LOG PROCESSING FRAMEWORK (SIH 26156)  "
echo "    Mode: Local Air-Gapped / Privacy-Preserving / OCSF Standard       "
echo "======================================================================"

# Cleanup handler on exit (Ctrl+C)
cleanup() {
    echo ""
    echo "[ULPF] Stopping all background processes..."
    kill $(jobs -p) 2>/dev/null || true
    echo "[ULPF] System shutdown complete."
}
trap cleanup EXIT INT TERM

# 1. Start the FastAPI Backend Server
echo "[1/4] Launching FastAPI Backend Server on port 8000..."
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
sleep 2

# 2. Start the React Vite Frontend
echo "[2/4] Launching React SOC Dashboard on port 5173..."
(cd frontend && npm run dev -- --host) &
FRONTEND_PID=$!
sleep 2

# 3. Check for Vector binary, run if available
mkdir -p /tmp/vector
if command -v vector &> /dev/null; then
    echo "[3/4] Vector.dev detected in PATH. Starting Vector Ingestion Engine on UDP 5140..."
    vector vector/vector.yaml &
    VECTOR_PID=$!
else
    echo "[3/4] Notice: 'vector' binary not in PATH."
    echo "      FastAPI's embedded high-speed UDP 514/5140/5514 listener is active and"
    echo "      executing the identical VRL pipeline (OCSF, PII Redaction, Threat Intel)."
    echo "      To run native vector when installed: vector vector/vector.yaml"
fi

# 4. Start the Mock Log Firehose Simulator
echo "[4/4] Starting Heterogeneous Log Firehose Simulator (~10 EPS)..."
python3 backend/simulate_firehose.py &
SIMULATOR_PID=$!

echo ""
echo "======================================================================"
echo " ✅ ALL SERVICES ARE LIVE & INTERCONNECTED!                           "
echo " 🌐 Web SOC Console: http://localhost:5173                            "
echo " 🔌 FastAPI Backend: http://localhost:8000                            "
echo " 📡 Ingestion Ports: UDP 127.0.0.1:5140 (Vector) / UDP 514 (Syslog)   "
echo " 🛑 Press Ctrl+C at any time to terminate all services                "
echo "======================================================================"
echo ""

# Wait for background jobs
wait
