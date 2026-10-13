"""Storage Archive Engine for ULPF (SIH 26156).

Storage Architecture & WORM Characteristics:
- Dual-tier storage architecture:
  1. Software-enforced append-only raw JSONL ledger (mode="a", never opened with "w") providing
     unmodified evidentiary preservation for chain-of-custody and lossless forensic recovery.
     NOTE ON WORM: This provides software-level append-only guarantees. True hardware WORM
     (Write Once, Read Many) requires dedicated optical media, hardware-level immutable S3 Object Lock,
     or kernel-level immutable file flags (chattr +i).
  2. High-performance SQLite database in WAL (Write-Ahead Logging) mode with indexes on:
     - event_id (UNIQUE primary key / indexed; rejects collisions with audit logging)
     - timestamp (ISO-8601 index)
     - src_ip (indexed)
     - dst_ip (indexed)
     - ocsf_class (indexed)
- Thread-safe single-writer queue for concurrency-safe WAL writes with connection pooling.
- Fast analytical queries for the SOC console (filtering, pagination, metrics aggregation).
- Audit log table for compliance tracking.
"""

import asyncio
try:
    import safe_serializer as json
except ImportError:
    from . import safe_serializer as json
import os
import queue
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from merkle_engine import IncrementalMerkleTree, MerkleTree
except ImportError:
    from backend.merkle_engine import IncrementalMerkleTree, MerkleTree

DB_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA cache_size = -64000;
PRAGMA mmap_size = 268435456;
PRAGMA temp_store = MEMORY;

CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    ocsf_class INTEGER NOT NULL,
    category_name TEXT,
    activity_name TEXT,
    severity_id INTEGER,
    severity TEXT,
    is_malicious INTEGER DEFAULT 0,
    threat_actor TEXT,
    pii_redacted INTEGER DEFAULT 0,
    pii_redacted_types TEXT,
    raw_sha256 TEXT,
    raw_base64 TEXT,
    sanitized_raw TEXT,
    normalized_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON security_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON security_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_ocsf_class ON security_events(ocsf_class);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity_id);
CREATE INDEX IF NOT EXISTS idx_events_category ON security_events(category_name);
CREATE INDEX IF NOT EXISTS idx_events_malicious ON security_events(is_malicious);
CREATE INDEX IF NOT EXISTS idx_events_pii ON security_events(pii_redacted);

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);
"""


class StorageArchive:
    def __init__(
        self,
        storage_dir: str,
        db_name: str = "ulpf_archive.db",
        jsonl_name: str = "lossless_archive.jsonl",
        max_jsonl_bytes: int = 50 * 1024 * 1024,  # 50MB per chunk default
        max_backups: int = 10
    ):
        self.storage_dir = os.path.abspath(storage_dir)
        os.makedirs(self.storage_dir, exist_ok=True)
        self.db_path = os.path.join(self.storage_dir, db_name)
        self.jsonl_path = os.path.join(self.storage_dir, jsonl_name)
        self.max_jsonl_bytes = max_jsonl_bytes
        self.max_backups = max_backups

        # Bounded FIFO queue with backpressure protection (100,000 pending items max)
        self._write_queue: queue.Queue = queue.Queue(maxsize=100000)
        self._stop_event = threading.Event()
        self._writer_thread = threading.Thread(target=self._writer_worker, daemon=True, name="ULPF-Storage-Writer")
        
        # Read-only query connection local storage
        self._local = threading.local()

        # Incremental Merkle Tree cache
        self._merkle_tree = IncrementalMerkleTree()
        self._merkle_lock = threading.Lock()
        self._merkle_row_index: Dict[str, int] = {}
        self._merkle_rows: List[Dict[str, Any]] = []

        # Initialize schema synchronously
        self._init_db()
        self._writer_thread.start()

    def _init_db(self):
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.executescript(DB_SCHEMA)
            conn.commit()

    def _get_read_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            self._local.conn = conn
        return self._local.conn

    def _writer_worker(self):
        """Dedicated single-writer thread ensuring serialized WAL writes without lock contention."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        
        jsonl_file = open(self.jsonl_path, "a", encoding="utf-8", buffering=1024 * 1024)

        def check_rotate_jsonl():
            nonlocal jsonl_file
            try:
                jsonl_file.flush()
                if os.path.exists(self.jsonl_path) and os.path.getsize(self.jsonl_path) >= self.max_jsonl_bytes:
                    jsonl_file.close()
                    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
                    rotated_path = f"{self.jsonl_path}.{ts}_{int(time.time()*1000)}"
                    os.rename(self.jsonl_path, rotated_path)
                    jsonl_file = open(self.jsonl_path, "a", encoding="utf-8", buffering=1024 * 1024)
            except Exception as re:
                print(f"[STORAGE ROTATION NOTICE] {re}")

        insert_sql = """
        INSERT INTO security_events (
            event_id, timestamp, src_ip, dst_ip, ocsf_class,
            category_name, activity_name, severity_id, severity,
            is_malicious, threat_actor, pii_redacted, pii_redacted_types,
            raw_sha256, raw_base64, sanitized_raw, normalized_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        audit_sql = """
        INSERT INTO audit_logs (timestamp, username, role, action, resource, status_code, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """

        def flush_events_safely(events, lines):
            if not events:
                return
            try:
                # Fast path: try batch insert
                conn.executemany(insert_sql, events)
                for line in lines:
                    check_rotate_jsonl()
                    jsonl_file.write(line + "\n")
                jsonl_file.flush()
                check_rotate_jsonl()
                conn.commit()
            except sqlite3.IntegrityError:
                # ID collision occurred: rollback and insert record-by-record
                conn.rollback()
                for row, line in zip(events, lines):
                    event_id = row[0]
                    try:
                        conn.execute(insert_sql, row)
                        jsonl_file.write(line + "\n")
                        conn.commit()
                    except sqlite3.IntegrityError:
                        conn.rollback()
                        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        conn.execute(
                            audit_sql,
                            (
                                ts,
                                "storage_engine",
                                "system",
                                "INSERT_COLLISION_REJECTED",
                                f"security_events/{event_id}",
                                409,
                                f"Rejected duplicate event_id {event_id}. Existing record was preserved intact."
                            )
                        )
                        conn.commit()
                jsonl_file.flush()
            except Exception as e:
                print(f"[STORAGE WRITER ERROR] {e}")

        batch_events = []
        batch_lines = []
        batch_audits = []
        last_flush = time.time()

        while not self._stop_event.is_set() or not self._write_queue.empty():
            try:
                item = self._write_queue.get(timeout=0.05)
                item_type = item[0]

                if item_type == "event":
                    event_row, line_str = item[1], item[2]
                    batch_events.append(event_row)
                    batch_lines.append(line_str)
                elif item_type == "audit":
                    batch_audits.append(item[1])
                elif item_type == "sync":
                    ack_event = item[1]
                    # Flush pending immediately
                    if batch_events:
                        flush_events_safely(batch_events, batch_lines)
                        batch_events.clear()
                        batch_lines.clear()
                    if batch_audits:
                        conn.executemany(audit_sql, batch_audits)
                        conn.commit()
                        batch_audits.clear()
                    ack_event.set()
                    self._write_queue.task_done()
                    continue

                self._write_queue.task_done()
            except queue.Empty:
                pass

            now = time.time()
            if batch_events and (len(batch_events) >= 100 or (now - last_flush) >= 0.1):
                flush_events_safely(batch_events, batch_lines)
                batch_events.clear()
                batch_lines.clear()
                last_flush = now

            if batch_audits and (len(batch_audits) >= 20 or (now - last_flush) >= 0.1):
                try:
                    conn.executemany(audit_sql, batch_audits)
                    conn.commit()
                except Exception as e:
                    print(f"[AUDIT WRITER ERROR] {e}")
                batch_audits.clear()
                last_flush = now

        # Final drain
        if batch_events:
            flush_events_safely(batch_events, batch_lines)
        if batch_audits:
            conn.executemany(audit_sql, batch_audits)
            conn.commit()

        jsonl_file.close()
        conn.close()

    def record_to_row(self, record: Dict[str, Any]) -> Tuple[Tuple, str]:
        norm = record.get("normalized_data") or {}
        trace = record.get("traceability") or {}

        event_id = record.get("id") or f"rec-{int(time.time()*1000)}-{os.urandom(4).hex()}"
        record["id"] = event_id
        timestamp = trace.get("ingest_timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        src_ip = norm.get("src_endpoint", {}).get("ip") or "0.0.0.0"
        dst_ip = norm.get("dst_endpoint", {}).get("ip") or "0.0.0.0"
        ocsf_class = int(norm.get("class_uid") or 4001)
        category_name = norm.get("category_name") or "Network Activity"
        activity_name = norm.get("activity_name") or "Traffic Flow"
        severity_id = int(norm.get("severity_id") or 1)
        severity = norm.get("severity") or "Informational"

        enrichment = norm.get("enrichment") or {}
        is_malicious = 1 if enrichment.get("is_malicious") else 0
        threat_actor = enrichment.get("threat_actor") or "None"

        compliance = norm.get("compliance") or {}
        pii_redacted = 1 if compliance.get("pii_redacted") else 0
        pii_types = compliance.get("pii_redacted_types") or []
        pii_types_str = json.dumps(pii_types)

        raw_sha256 = trace.get("raw_sha256") or ""
        raw_base64 = trace.get("raw_base64") or ""
        sanitized_raw = trace.get("sanitized_raw") or ""
        normalized_json = json.dumps(record)

        row = (
            event_id, timestamp, src_ip, dst_ip, ocsf_class,
            category_name, activity_name, severity_id, severity,
            is_malicious, threat_actor, pii_redacted, pii_types_str,
            raw_sha256, raw_base64, sanitized_raw, normalized_json
        )
        return row, normalized_json

    def is_memory_pressure_high(self) -> bool:
        """Checks if system RAM usage exceeds 90% threshold for graceful degradation."""
        try:
            import psutil
            return psutil.virtual_memory().percent >= 90.0
        except Exception:
            return False

    def ingest_record(self, record: Dict[str, Any]):
        """Asynchronous enqueue of security log record.

        Graceful Degradation:
        Monitors psutil.virtual_memory().percent. If RAM hits 90%, stops SQLite parsing
        and strictly spools raw logs to disk until memory frees up, preventing OOM crashes.
        """
        # Check for extreme memory pressure
        if self.is_memory_pressure_high():
            trace = record.get("traceability") or {}
            raw_text = trace.get("sanitized_raw") or trace.get("raw_base64") or str(record)
            spool_file = os.path.join(self.storage_dir, "emergency_spool.raw")
            try:
                with open(spool_file, "a", encoding="utf-8") as sf:
                    sf.write(f"{time.time()}|{raw_text}\n")
            except Exception:
                pass
            return

        row, line_str = self.record_to_row(record)
        self._write_queue.put(("event", row, line_str))

    def ingest_audit(self, username: str, role: str, action: str, resource: str, status_code: int, details: str = ""):
        """Enqueue audit log entry."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._write_queue.put(("audit", (ts, username, role, action, resource, status_code, details)))

    def flush(self):
        """Synchronously wait until all queued writes are committed to disk."""
        ack = threading.Event()
        self._write_queue.put(("sync", ack))
        ack.wait(timeout=10.0)

    # --------------------------------------------------------------------------
    # SOC QUERY APIs (Using SQLite WAL index)
    # --------------------------------------------------------------------------
    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_read_conn()
        cursor = conn.execute(
            "SELECT normalized_json FROM security_events WHERE event_id = ? OR raw_sha256 = ? LIMIT 1",
            (event_id, event_id)
        )
        row = cursor.fetchone()
        if row:
            return json.loads(row["normalized_json"])
        return None

    def query_recent_events(
        self,
        limit: int = 100,
        offset: int = 0,
        ocsf_class: Optional[int] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        only_malicious: bool = False,
        only_pii: bool = False,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        conn = self._get_read_conn()
        clauses = []
        params: List[Any] = []

        if ocsf_class is not None:
            clauses.append("ocsf_class = ?")
            params.append(ocsf_class)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip:
            clauses.append("dst_ip = ?")
            params.append(dst_ip)
        if only_malicious:
            clauses.append("is_malicious = 1")
        if only_pii:
            clauses.append("pii_redacted = 1")
        if search:
            clauses.append("(sanitized_raw LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR threat_actor LIKE ?)")
            p = f"%{search}%"
            params.extend([p, p, p, p])

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT normalized_json FROM security_events {where_sql} ORDER BY rowid DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = conn.execute(sql, params)
        return [json.loads(r["normalized_json"]) for r in cursor.fetchall()]

    def count_events(self) -> int:
        conn = self._get_read_conn()
        cursor = conn.execute("SELECT COUNT(*) FROM security_events")
        return cursor.fetchone()[0]

    def get_metrics_summary(self) -> Dict[str, Any]:
        conn = self._get_read_conn()
        row = conn.execute("""
            SELECT 
                COUNT(*) as total,
                TOTAL(is_malicious) as malicious,
                TOTAL(pii_redacted) as pii
            FROM security_events
        """).fetchone()

        total = int(row["total"] or 0)
        malicious = int(row["malicious"] or 0)
        pii = int(row["pii"] or 0)
        
        cursor = conn.execute("SELECT category_name, COUNT(*) FROM security_events GROUP BY category_name")
        dist = {r[0] or "Other": r[1] for r in cursor.fetchall()}

        return {
            "total_buffered": total,
            "malicious_count": malicious,
            "pii_redacted_count": pii,
            "event_distribution": dist,
        }

    def query_audit_logs(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        conn = self._get_read_conn()
        cursor = conn.execute(
            "SELECT audit_id, timestamp, username, role, action, resource, status_code, details "
            "FROM audit_logs ORDER BY audit_id DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_merkle_tree(self, limit: int = 1000) -> Tuple[Any, List[Dict[str, Any]]]:
        """
        Builds or returns cached RFC 6962 Merkle Tree over security events.
        Maintains an in-memory incremental cache for high throughput.
        """
        with self._merkle_lock:
            conn = self._get_read_conn()
            cursor = conn.execute(
                "SELECT rowid, event_id, timestamp, raw_sha256 FROM security_events ORDER BY rowid ASC LIMIT ?",
                (limit,)
            )
            rows = [dict(r) for r in cursor.fetchall()]
            
            # If cache count matches rows, use cached tree
            if len(self._merkle_tree) == len(rows) and self._merkle_rows == rows:
                return self._merkle_tree, rows

            # Re-seed incremental tree
            self._merkle_tree = IncrementalMerkleTree()
            self._merkle_rows = rows
            self._merkle_row_index = {r["event_id"]: idx for idx, r in enumerate(rows)}
            
            leaves = [
                f"{r['event_id']}:{r['timestamp']}:{r['raw_sha256'] or ''}".encode("utf-8")
                for r in rows
            ]
            self._merkle_tree.append_batch(leaves)
            return self._merkle_tree, rows

    def get_merkle_proof_for_event(self, event_id: str, limit: int = 1000) -> Optional[Dict[str, Any]]:
        """
        Retrieves RFC 6962 inclusion proof for a given event_id using O(1) indexed lookup.
        """
        tree, rows = self.get_merkle_tree(limit=limit)
        with self._merkle_lock:
            target_idx = self._merkle_row_index.get(event_id)
            if target_idx is None or target_idx >= len(rows):
                return None
            target_row = rows[target_idx]

            proof = tree.get_inclusion_proof(target_idx)
            leaf_data = f"{target_row['event_id']}:{target_row['timestamp']}:{target_row['raw_sha256'] or ''}".encode("utf-8")

            return {
                "event_id": event_id,
                "leaf_index": target_idx,
                "total_leaves": len(rows),
                "leaf_data": leaf_data.decode("utf-8"),
                "merkle_root": tree.root_hex,
                "proof": proof,
            }

    def close(self):
        self._stop_event.set()
        self._writer_thread.join(timeout=5.0)
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
