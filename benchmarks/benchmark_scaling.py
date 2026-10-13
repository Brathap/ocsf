#!/usr/bin/env python3
"""ULPF Multiprocessing Scale Benchmark.

Measures and reports EPS at 1, 2, 4, 8 stateless workers with:
- Per-shard isolated SQLite WAL databases (no shared writer lock)
- Per-shard Merkle ledgers and cross-shard RFC 6962 aggregator
- Same workload and batching method across all runs
- 3 iterations per worker count, reporting median EPS
- Host machine specifications, load averages, and arithmetic vs measured scale
"""

import os
import sys
import time
import shutil
import platform
import statistics
import multiprocessing as mp

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from multi_worker_ingest import MultiWorkerPipeline

SAMPLE_LOGS = [
    "%ASA-6-302013: Built inbound TCP connection 123456 for outside:198.51.100.4/443 to inside:10.0.0.50/54321",
    "CEF:0|ArcSight|WAF|1.0|SQLi|SQL Injection Attack|7|src=203.0.113.19 dst=10.0.0.10 spt=54123 dpt=80",
    "date=2026-10-06 time=09:30:00 devname=\"FG-500E\" devid=\"FG500E4Q18000001\" eventtime=1696584600123456789 type=traffic srcip=192.168.1.100 srcport=54321 dstip=198.51.100.25 dstport=443 proto=6 action=accept",
    "<14>1 2026-10-06T09:30:00.000Z srx-edge01 RT_FLOW - RT_FLOW_SESSION_CREATE: [junos@2636.1.1.1.2.40] 192.168.10.5/51234 -> 203.0.113.80/443",
    "filterlog[12345]: 100,1,,1000000100,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,192.168.2.10,198.51.100.30,55123,443",
]


def run_scaling_benchmark():
    sources_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sources"))
    bench_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "tmp_bench_shards"))
    if os.path.exists(bench_dir):
        shutil.rmtree(bench_dir)
    os.makedirs(bench_dir, exist_ok=True)

    cpu_count = mp.cpu_count()
    proc = platform.processor() or "x86_64"
    system = platform.system()
    release = platform.release()
    load1, load5, load15 = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

    print("==========================================================================================")
    print("                     AEGISGUARD-ULPF MULTIPROCESSING SCALING BENCHMARK                    ")
    print("==========================================================================================")
    print(f"Machine Spec : {system} {release} | CPU Cores: {cpu_count} | Arch: {proc}")
    print(f"System Load  : 1m: {load1:.2f}, 5m: {load5:.2f}, 15m: {load15:.2f}")
    print(f"Target Scale : 1,000,000,000 events/day = 11,574 EPS sustained (Arithmetic requirement)")
    print(f"Workload     : End-to-end routing + byte lineage + per-shard SQLite WAL + shard Merkle ledger")
    print(f"Methodology  : 3 runs per worker level; reporting median EPS")
    print("------------------------------------------------------------------------------------------")
    print(f"{'Workers':<10} | {'Events / Run':<14} | {'Run 1 (EPS)':<12} | {'Run 2 (EPS)':<12} | {'Run 3 (EPS)':<12} | {'Median EPS':<12}")
    print("------------------------------------------------------------------------------------------")

    worker_counts = [1, 2, 4, 8]
    events_per_run = 10000
    workload = [SAMPLE_LOGS[i % len(SAMPLE_LOGS)] for i in range(events_per_run)]

    results = []

    for w in worker_counts:
        eps_runs = []
        for run_idx in range(3):
            db_base = os.path.join(bench_dir, f"scale_w{w}_r{run_idx}")
            pipe = MultiWorkerPipeline(num_workers=w, sources_dir=sources_dir, base_db_path=db_base)
            pipe.start()

            t_start = time.perf_counter()
            pipe.dispatch(workload, batch_size=200)
            res = pipe.join_and_finalize()
            t_duration = time.perf_counter() - t_start

            eps = events_per_run / t_duration if t_duration > 0 else 0
            eps_runs.append(eps)

        med_eps = statistics.median(eps_runs)
        print(f"{w:<10} | {events_per_run:<14} | {eps_runs[0]:<12.0f} | {eps_runs[1]:<12.0f} | {eps_runs[2]:<12.0f} | {med_eps:<12.0f}")
        results.append({
            "workers": w,
            "events": events_per_run,
            "runs": [round(x, 1) for x in eps_runs],
            "median_eps": round(med_eps, 1)
        })

    print("------------------------------------------------------------------------------------------")
    print("\n[!] CAPACITY ANALYSIS:")
    print(f"  • Single-Worker Measured Median : {results[0]['median_eps']:,.0f} EPS")
    print(f"  • Best Multi-Worker Median     : {max(r['median_eps'] for r in results):,.0f} EPS")
    print(f"  • 1 Billion / Day Requirement  : 11,574.07 EPS (1,000,000,000 / 86,400s)")
    best_eps = max(r['median_eps'] for r in results)
    if best_eps >= 11574:
        print("  • Verdict: Measured throughput SUSTAINS 1B/day on this host!")
    else:
        req_workers = int(11574 / results[0]['median_eps']) + 1
        print(f"  • Cluster Projection: Requires ~{req_workers} parallel workers to sustain 11,574 EPS with full disk persistence.")

    if os.path.exists(bench_dir):
        shutil.rmtree(bench_dir)


if __name__ == "__main__":
    run_scaling_benchmark()
