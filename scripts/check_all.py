#!/usr/bin/env python3
"""ULPF Single-Command Verification Runner (SIH 26156).

Executes:
1. Full Pytest Regression Suite (69+ tests: Merkle, PII, Reconstruction, Egress, Lineage, Intelligence, Drift, Storage).
2. Air-Gap & Socket Egress Verification.
3. Stream Ingestion Benchmark (10,000 events throughput check).
"""

import sys
import os
import subprocess
import time

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def run_step(title, command):
    print(f"\n=======================================================")
    print(f"  STEP: {title}")
    print(f"=======================================================")
    t0 = time.time()
    res = subprocess.run(command, shell=True, cwd=BASE_DIR)
    duration = time.time() - t0
    if res.returncode != 0:
        print(f"\n[FAIL] Step '{title}' failed with exit code {res.returncode} in {duration:.2f}s")
        sys.exit(res.returncode)
    else:
        print(f"\n[PASS] Step '{title}' completed successfully in {duration:.2f}s")

def main():
    print("*******************************************************")
    print("      ULPF SIH 26156 - COMPLETE VERIFICATION RUNNER     ")
    print("*******************************************************")
    
    # 1. Tests
    run_step("Pytest Comprehensive Regression Suite", f"{sys.executable} -m pytest tests/ -v")

    # 2. Air-Gap
    run_step("Air-Gap & Socket Egress Audit", f"{sys.executable} scripts/verify_airgap.py")

    # 3. Benchmark
    run_step("Empirical Performance Benchmark (10,000 logs)", f"{sys.executable} benchmarks/benchmark_end_to_end.py 10000")

    print("\n*******************************************************")
    print("  ALL SIH 26156 VALIDATION CRITERIA 100% SATISFIED!   ")
    print("*******************************************************\n")

if __name__ == "__main__":
    main()
