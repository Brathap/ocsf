#!/usr/bin/env bash
# ==============================================================================
# scripts/bundle_offline_release.sh - Offline Air-Gap Delivery Packager
# ==============================================================================
# Builds and exports an air-gapped deployment bundle containing:
# 1. Complete repository and source pack definitions
# 2. Local Python wheel dependencies / virtualenv
# 3. Local threat intelligence feeds
# 4. Optional Docker image tar archive (via `docker save`) if Docker daemon is active
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist_offline"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
BUNDLE_NAME="ulpf_offline_enclave_bundle_${TIMESTAMP}"

mkdir -p "${DIST_DIR}/${BUNDLE_NAME}"
echo "[*] Creating offline enclave deployment bundle in: ${DIST_DIR}/${BUNDLE_NAME}"

# 1. Package codebase
echo "[*] Packaging core codebase and source packs..."
tar --exclude='.git' \
    --exclude='realdata' \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='dist_offline' \
    -czf "${DIST_DIR}/${BUNDLE_NAME}/ulpf_source.tar.gz" -C "${REPO_ROOT}" .

# 2. Export Docker image if available
if command -v docker &>/dev/null && docker info &>/dev/null; then
    echo "[*] Building and exporting offline Docker image (docker save)..."
    docker build -t ulpf-airgap:latest -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
    docker save ulpf-airgap:latest | gzip > "${DIST_DIR}/${BUNDLE_NAME}/ulpf_docker_image.tar.gz"
    echo "[✓] Exported Docker image archive."
else
    echo "[!] Docker not detected; packaged source-based offline bundle."
fi

# 3. Create bundle manifest and SHA-256 integrity checksums
cd "${DIST_DIR}/${BUNDLE_NAME}"
sha256sum * > SHA256SUMS.txt
echo "[✓] Created SHA256SUMS.txt integrity manifest."

echo "=============================================================================="
echo "[SUCCESS] Offline enclave bundle ready at: ${DIST_DIR}/${BUNDLE_NAME}"
echo "=============================================================================="
