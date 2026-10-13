"""Multiprocessing Ingest Engine and Sharded Merkle Ledger.

Implements N stateless worker processes with per-shard Merkle hash chains
and a cross-shard verification aggregator for high-throughput scaling.
"""

import os
import sys
import time
import json
import sqlite3
import hashlib
import multiprocessing as mp
from typing import List, Dict, Any, Tuple, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from source_packs.registry import SourcePackRegistry
from lineage_engine import LineageEngine
from merkle_engine import MerkleTree, hash_leaf, hash_children


def worker_ingest_loop(
    worker_id: int,
    task_queue: mp.Queue,
    result_queue: mp.Queue,
    sources_dir: str,
    db_path: str
):
    """Stateless worker loop: ingests logs, routes to packs, computes lineage & leaf hashes."""
    registry = SourcePackRegistry(sources_dir)
    
    # Per-worker local SQLite connection
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shard_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shard_id INTEGER,
            raw_sha256 TEXT,
            class_uid INTEGER,
            activity_name TEXT,
            created_at REAL
        );
    """)
    conn.commit()

    processed_count = 0
    leaf_hashes: List[bytes] = []

    while True:
        try:
            batch = task_queue.get()
            if batch is None:  # Sentinel
                break

            rows_to_insert = []
            for raw_line in batch:
                routed = registry.route_and_parse(raw_line)
                if routed:
                    pack, extracted, ocsf = routed
                    envelope = LineageEngine.build_envelope(
                        raw_text=raw_line,
                        normalized_data=ocsf,
                        parser_id=pack.pack_id,
                        pack_version=pack.version,
                        extracted_fields=extracted
                    )
                else:
                    # Enterprise Fix: BaseEvent OCSF v1.1.0 fallback with source IP, timestamp, and review status
                    fallback_ocsf = SourcePackRegistry.create_fallback_base_event(raw_line)
                    envelope = LineageEngine.build_envelope(
                        raw_text=raw_line,
                        normalized_data=fallback_ocsf,
                        parser_id="generic-unparsed"
                    )

                raw_sha = envelope["traceability"]["raw_sha256"]
                leaf_hash = hash_leaf(raw_sha.encode("ascii"))
                leaf_hashes.append(leaf_hash)
                rows_to_insert.append((
                    worker_id,
                    raw_sha,
                    envelope["normalized_data"].get("class_uid", 6001),
                    envelope["normalized_data"].get("activity_name", "event"),
                    time.time()
                ))
                processed_count += 1

            conn.executemany(
                "INSERT INTO shard_records (shard_id, raw_sha256, class_uid, activity_name, created_at) VALUES (?, ?, ?, ?, ?)",
                rows_to_insert
            )
            conn.commit()
            task_queue.task_done()

        except Exception as e:
            # Report or log error safely
            pass

    # Build local shard Merkle tree
    tree = MerkleTree(leaf_hashes)
    shard_root = tree.root_hex
    conn.close()

    result_queue.put({
        "worker_id": worker_id,
        "processed_count": processed_count,
        "shard_root": shard_root,
        "leaf_count": len(leaf_hashes)
    })


class MultiWorkerPipeline:
    """Orchestrates N stateless workers and aggregates shard Merkle roots."""

    def __init__(self, num_workers: int, sources_dir: str, base_db_path: str):
        self.num_workers = num_workers
        self.sources_dir = sources_dir
        self.base_db_path = base_db_path
        self.task_queues: List[mp.JoinableQueue] = []
        self.result_queue = mp.Queue()
        self.workers: List[mp.Process] = []

    def start(self):
        for w_id in range(self.num_workers):
            t_q = mp.JoinableQueue(maxsize=100)
            self.task_queues.append(t_q)
            db_p = f"{self.base_db_path}_shard_{w_id}.db"
            p = mp.Process(
                target=worker_ingest_loop,
                args=(w_id, t_q, self.result_queue, self.sources_dir, db_p)
            )
            p.daemon = True
            p.start()
            self.workers.append(p)

    def dispatch(self, logs: List[str], batch_size: int = 100):
        # Round-robin dispatch batches to worker queues
        for i in range(0, len(logs), batch_size):
            chunk = logs[i:i + batch_size]
            w_idx = (i // batch_size) % self.num_workers
            self.task_queues[w_idx].put(chunk)

    def join_and_finalize(self) -> Dict[str, Any]:
        # Wait for all queues to drain
        for t_q in self.task_queues:
            t_q.join()
            t_q.put(None)  # Sentinel

        shard_results = []
        for _ in range(self.num_workers):
            shard_results.append(self.result_queue.get(timeout=30))

        for p in self.workers:
            p.join(timeout=5)

        # Cross-shard ledger: build top-level Merkle tree over all shard roots
        shard_roots = [bytes.fromhex(r["shard_root"]) for r in shard_results if r.get("shard_root")]
        top_tree = MerkleTree(shard_roots)

        return {
            "num_workers": self.num_workers,
            "total_processed": sum(r["processed_count"] for r in shard_results),
            "top_root_hex": top_tree.root_hex,
            "shard_results": shard_results
        }
