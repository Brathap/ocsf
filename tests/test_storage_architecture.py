"""Tests for ULPF Storage Architecture (Requirement 1).

Verifies:
1. SQLite WAL mode table with indexes on event_id, timestamp, src_ip, dst_ip, ocsf_class.
2. Ingestion of 10,000 events without data loss.
3. Query latency stays low (< 50ms) across indexed columns.
4. Concurrency safety (multiple threads ingesting simultaneously).
5. Lossless JSONL append-only audit trail retains exact event count.
"""

import os
import shutil
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from storage_engine import StorageArchive


class TestStorageArchitecture(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ulpf_storage_test_")
        self.archive = StorageArchive(self.temp_dir)

    def tearDown(self):
        self.archive.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_and_indexes(self):
        """Confirm WAL mode and indexes on required columns."""
        conn = self.archive._get_read_conn()
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal", "Database must be in WAL mode")

        # Verify indexes
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        indexes = {r[0] for r in cursor.fetchall()}
        self.assertIn("idx_events_timestamp", indexes)
        self.assertIn("idx_events_src_ip", indexes)
        self.assertIn("idx_events_dst_ip", indexes)
        self.assertIn("idx_events_ocsf_class", indexes)

    def test_ingest_10k_events_and_query_latency(self):
        """Ingest 10,000 events and confirm zero data loss + query latency < 50ms."""
        total_events = 10000
        start_time = time.time()

        for i in range(total_events):
            record = {
                "id": f"event-{i:05d}",
                "traceability": {
                    "raw_sha256": f"hash-{i:05d}",
                    "raw_base64": "ZXhhbXBsZQ==",
                    "ingest_timestamp": f"2026-09-26T12:{i % 60:02d}:00Z",
                    "sanitized_raw": f"Denied TCP from 192.168.1.{i % 250} to 10.0.0.1 port 80",
                },
                "normalized_data": {
                    "class_uid": 4001 if i % 2 == 0 else 3002,
                    "category_name": "Network Activity" if i % 2 == 0 else "Identity & Access Management",
                    "activity_name": "Firewall Deny",
                    "severity_id": 4 if i % 10 == 0 else 1,
                    "severity": "High" if i % 10 == 0 else "Informational",
                    "src_endpoint": {"ip": f"192.168.1.{i % 250}"},
                    "dst_endpoint": {"ip": "10.0.0.1"},
                    "enrichment": {
                        "is_malicious": (i % 20 == 0),
                        "threat_actor": "APT29" if (i % 20 == 0) else "None",
                    },
                    "compliance": {
                        "pii_redacted": (i % 50 == 0),
                        "pii_redacted_types": ["aadhaar"] if (i % 50 == 0) else [],
                    },
                }
            }
            self.archive.ingest_record(record)

        # Flush write queue to SQLite and JSONL
        self.archive.flush()
        ingest_duration = time.time() - start_time
        print(f"\n[BENCHMARK] Ingested {total_events} events in {ingest_duration:.2f}s ({total_events/ingest_duration:.0f} eps)")

        # 1. Confirm zero data loss
        count = self.archive.count_events()
        self.assertEqual(count, total_events, f"Expected {total_events} events in SQLite table, got {count}")

        # Check raw JSONL line count
        with open(self.archive.jsonl_path, "r", encoding="utf-8") as f:
            jsonl_lines = sum(1 for _ in f)
        self.assertEqual(jsonl_lines, total_events, f"Expected {total_events} lines in JSONL archive, got {jsonl_lines}")

        # 2. Query latency benchmarks across indexed fields (requirement states < 50ms)
        # Pre-warm connection
        self.archive._get_read_conn()
        
        # Query by event_id (primary key index)
        q_start = time.perf_counter()
        ev = self.archive.get_event_by_id("event-05432")
        q_lat_ms = (time.perf_counter() - q_start) * 1000
        self.assertIsNotNone(ev)
        self.assertLess(q_lat_ms, 50.0, f"Query by ID latency too high: {q_lat_ms:.2f}ms")

        # Query by src_ip index
        q_start = time.perf_counter()
        ip_results = self.archive.query_recent_events(limit=50, src_ip="192.168.1.100")
        ip_lat_ms = (time.perf_counter() - q_start) * 1000
        self.assertGreater(len(ip_results), 0)
        self.assertLess(ip_lat_ms, 30.0, f"Query by src_ip latency too high: {ip_lat_ms:.2f}ms")

        # Query by OCSF Class index
        q_start = time.perf_counter()
        class_results = self.archive.query_recent_events(limit=100, ocsf_class=3002)
        class_lat_ms = (time.perf_counter() - q_start) * 1000
        self.assertEqual(len(class_results), 100)
        self.assertLess(class_lat_ms, 30.0, f"Query by OCSF class latency too high: {class_lat_ms:.2f}ms")

        # Aggregated metrics calculation
        q_start = time.perf_counter()
        metrics = self.archive.get_metrics_summary()
        m_lat_ms = (time.perf_counter() - q_start) * 1000
        self.assertEqual(metrics["total_buffered"], total_events)
        self.assertEqual(metrics["malicious_count"], total_events // 20)
        self.assertEqual(metrics["pii_redacted_count"], total_events // 50)
        self.assertLess(m_lat_ms, 120.0, f"Metrics query latency too high: {m_lat_ms:.2f}ms")

        print(f"[BENCHMARK] Latency: ID={q_lat_ms:.3f}ms | src_ip={ip_lat_ms:.3f}ms | class={class_lat_ms:.3f}ms | metrics={m_lat_ms:.3f}ms")

    def test_concurrent_multithreaded_writers(self):
        """Confirm concurrent multi-threaded ingestion safety without deadlocks or corrupted rows."""
        num_threads = 8
        events_per_thread = 500
        total_expected = num_threads * events_per_thread

        def worker(thread_idx):
            for i in range(events_per_thread):
                eid = f"worker-{thread_idx}-{i}"
                rec = {
                    "id": eid,
                    "traceability": {
                        "raw_sha256": f"hash-{eid}",
                        "sanitized_raw": f"Thread worker {thread_idx} log entry {i}"
                    },
                    "normalized_data": {
                        "class_uid": 4001,
                        "src_endpoint": {"ip": f"10.0.{thread_idx}.{i % 250}"}
                    }
                }
                self.archive.ingest_record(rec)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            list(executor.map(worker, range(num_threads)))

        self.archive.flush()
        count = self.archive.count_events()
        self.assertEqual(count, total_expected, f"Expected {total_expected} concurrent events, got {count}")

    def test_duplicate_event_id_collision_rejection(self):
        """Confirm that duplicate event_id is rejected without silent overwrite, and collision is logged to audit."""
        rec1 = {
            "id": "collision-test-id-001",
            "traceability": {
                "raw_sha256": "hash-original",
                "sanitized_raw": "Original payload content"
            },
            "normalized_data": {
                "class_uid": 4001,
                "src_endpoint": {"ip": "10.0.0.1"}
            }
        }
        # Attempt to insert identical ID with different payload
        rec2 = {
            "id": "collision-test-id-001",
            "traceability": {
                "raw_sha256": "hash-overwriter",
                "sanitized_raw": "Malicious attempt to overwrite original payload"
            },
            "normalized_data": {
                "class_uid": 4001,
                "src_endpoint": {"ip": "198.51.100.99"}
            }
        }

        self.archive.ingest_record(rec1)
        self.archive.flush()

        self.archive.ingest_record(rec2)
        self.archive.flush()

        # Verify original record remained intact (not overwritten)
        fetched = self.archive.get_event_by_id("collision-test-id-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["traceability"]["raw_sha256"], "hash-original")
        self.assertEqual(fetched["traceability"]["sanitized_raw"], "Original payload content")

        # Verify collision was logged into audit_logs table
        audits = self.archive.query_audit_logs(limit=10)
        rejection_logs = [
            a for a in audits
            if a.get("action") == "INSERT_COLLISION_REJECTED" and "collision-test-id-001" in a.get("resource", "")
        ]
        self.assertGreaterEqual(len(rejection_logs), 1, "Collision must be recorded in audit logs")
        self.assertEqual(rejection_logs[0]["status_code"], 409)

    def test_automatic_jsonl_rotation(self):
        """Confirm that JSONL rotates when byte threshold is exceeded without dropping records."""
        # Create a small archive with a 2KB threshold
        small_archive_dir = os.path.join(self.temp_dir, "small_archive")
        small_archive = StorageArchive(small_archive_dir, max_jsonl_bytes=2048)

        try:
            for i in range(50):
                rec = {
                    "id": f"rot-{i}",
                    "traceability": {
                        "raw_sha256": f"hash-{i}",
                        "sanitized_raw": "A" * 150  # ~150 bytes per line
                    },
                    "normalized_data": {"class_uid": 4001}
                }
                small_archive.ingest_record(rec)
            small_archive.flush()

            files = os.listdir(small_archive_dir)
            jsonl_files = [f for f in files if "lossless_archive.jsonl" in f]
            # Should have rotated at least once
            self.assertGreaterEqual(len(jsonl_files), 2, f"Expected rotated files, found {jsonl_files}")
        finally:
            small_archive.close()


if __name__ == "__main__":
    unittest.main()
