"""Forensic Quarantine Subsystem for ULPF.

Stores, indexes, and manages unparseable, malformed, or policy-rejected security telemetry:
- Preserves raw bytes without transformation
- Records failure classification (e.g. MALFORMED_SYNTAX, UNKNOWN_SCHEMA, INTEGRITY_MISMATCH)
- Implements SQLite index for SOC analyst queries, filtering, and inspection
- Provides safe event replay API for re-running quarantined events after parser upgrades
"""

import os
try:
    import safe_serializer as json
except ImportError:
    from . import safe_serializer as json
import sqlite3
import hashlib
import time
from typing import Dict, Any, List, Optional, Tuple


QUARANTINE_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS quarantined_events (
    quarantine_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_hint TEXT,
    failure_category TEXT NOT NULL,
    failure_reason TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    raw_payload TEXT NOT NULL,
    metadata_json TEXT,
    status TEXT DEFAULT 'PENDING'  -- PENDING, REPLAYED, DISMISSED
);

CREATE INDEX IF NOT EXISTS idx_quarantine_ts ON quarantined_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_quarantine_cat ON quarantined_events(failure_category);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantined_events(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_sha ON quarantined_events(raw_sha256);
"""


class QuarantineManager:
    """Enterprise quarantine store for unparsed, corrupted, or drifted security telemetry."""

    def __init__(self, storage_dir: str):
        self.storage_dir = os.path.abspath(storage_dir)
        os.makedirs(self.storage_dir, exist_ok=True)
        self.db_path = os.path.join(self.storage_dir, "quarantine.db")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.executescript(QUARANTINE_SCHEMA)

    def quarantine_event(
        self,
        raw_log: str,
        failure_category: str,
        failure_reason: str,
        source_hint: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Persists a failed event into the quarantine database."""
        raw_bytes = raw_log.encode("utf-8", errors="replace")
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        qid = f"quar-{int(time.time()*1000)}-{raw_sha256[:8]}"
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        meta_str = json.dumps(metadata or {})

        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO quarantined_events 
                   (quarantine_id, timestamp, source_hint, failure_category, failure_reason, raw_sha256, raw_payload, metadata_json, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')""",
                (qid, ts, source_hint, failure_category, failure_reason, raw_sha256, raw_log, meta_str)
            )
        return qid

    def list_quarantined(
        self,
        status: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Queries quarantined telemetry with filtering and pagination."""
        query = "SELECT * FROM quarantined_events WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if category:
            query += " AND failure_category = ?"
            params.append(category)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_event(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """Fetches a single quarantined record by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM quarantined_events WHERE quarantine_id = ?", (quarantine_id,)).fetchone()
            return dict(row) if row else None

    def mark_status(self, quarantine_id: str, new_status: str) -> bool:
        """Updates the status of a quarantined record (e.g. REPLAYED, DISMISSED)."""
        with self._get_connection() as conn:
            cur = conn.execute("UPDATE quarantined_events SET status = ? WHERE quarantine_id = ?", (new_status, quarantine_id))
            return cur.rowcount > 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns aggregated breakdown of quarantined event categories."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM quarantined_events").fetchone()[0]
            pending = conn.execute("SELECT COUNT(*) FROM quarantined_events WHERE status = 'PENDING'").fetchone()[0]
            categories = conn.execute("SELECT failure_category, COUNT(*) FROM quarantined_events GROUP BY failure_category").fetchall()
            return {
                "total_quarantined": total,
                "pending_review": pending,
                "by_category": {cat: count for cat, count in categories}
            }
