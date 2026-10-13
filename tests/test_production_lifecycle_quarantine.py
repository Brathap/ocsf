"""Production-Grade Comprehensive Test Suite for Lifecycle, Quarantine, and Ingestion Gateway."""

import os
import sys
import pytest
import asyncio
import tempfile
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from source_packs.lifecycle import SourcePackLifecycleManager, SourcePackSecurityError
from quarantine_engine import QuarantineManager
from ingestion_gateway import IngestionQueueManager


class TestSourcePackLifecycleAndRollback:
    def test_lifecycle_validation_and_promotion(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = SourcePackLifecycleManager(tmpdir)
            sample_yaml = """
metadata:
  vendor: Fortinet
  product: FortiGate
  version: 1.0.0
  priority: 110
detection:
  match_regex:
    - 'type="traffic"'
parser:
  type: regex
  pattern: 'type="traffic" src=(?P<src_ip>[\\d\\.]+)'
mappings:
  src_endpoint.ip: src_ip
"""
            success, msg, meta = mgr.promote_candidate_pack(sample_yaml, actor="soc_analyst")
            assert success is True
            assert meta["version"] == "1.0.0"

            # Check active file created
            active_file = os.path.join(tmpdir, "vendors", "fortinet_fortigate.yaml")
            assert os.path.exists(active_file)

    def test_redos_pattern_rejection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = SourcePackLifecycleManager(tmpdir)
            malicious_yaml = """
metadata:
  vendor: BadActor
  product: ReDoSBomb
  version: 1.0.0
detection:
  match_regex:
    - '(a+)+'
parser:
  type: regex
  pattern: '(a+)+$'
"""
            success, msg, _ = mgr.promote_candidate_pack(malicious_yaml)
            assert success is False
            assert "catastrophic backtracking" in msg.lower() or "redos" in msg.lower()

    def test_atomic_rollback_to_previous_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = SourcePackLifecycleManager(tmpdir)
            v1_yaml = """
metadata:
  vendor: PaloAlto
  product: PANOS
  version: 1.0.0
detection:
  match_regex:
    - 'TRAFFIC'
parser:
  type: regex
  pattern: 'TRAFFIC,(?P<src_ip>[\\d\\.]+)'
"""
            mgr.promote_candidate_pack(v1_yaml, actor="engineer_v1")

            v2_yaml = """
metadata:
  vendor: PaloAlto
  product: PANOS
  version: 2.0.0
detection:
  match_regex:
    - 'TRAFFIC'
parser:
  type: regex
  pattern: 'TRAFFIC,NEW_FORMAT,(?P<src_ip>[\\d\\.]+)'
"""
            mgr.promote_candidate_pack(v2_yaml, actor="engineer_v2")

            # Verify history contains v1
            history = mgr.list_version_history("PaloAlto", "PANOS")
            assert len(history) >= 1
            assert any(h["version"] == "1.0.0" for h in history)

            # Rollback to v1
            success, msg = mgr.rollback_pack("PaloAlto", "PANOS", target_version="1.0.0")
            assert success is True
            assert "rolled back" in msg.lower()

            active_file = os.path.join(tmpdir, "vendors", "paloalto_panos.yaml")
            with open(active_file, "r") as f:
                active_data = yaml.safe_load(f)
                assert active_data["metadata"]["version"] == "1.0.0"


class TestQuarantineSubsystem:
    def test_quarantine_storage_and_query(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            qm = QuarantineManager(tmpdir)
            raw = "CORRUPTED_PACKET \x00\xff invalid header data"
            qid = qm.quarantine_event(
                raw_log=raw,
                failure_category="MALFORMED_HEADER",
                failure_reason="Non-printable binary bytes detected",
                source_hint="edge_gw01"
            )
            assert qid.startswith("quar-")

            events = qm.list_quarantined()
            assert len(events) == 1
            assert events[0]["failure_category"] == "MALFORMED_HEADER"
            assert events[0]["raw_payload"] == raw

            # Stats check
            stats = qm.get_stats()
            assert stats["total_quarantined"] == 1
            assert stats["pending_review"] == 1


class TestIngestionGatewayQueue:
    def test_bounded_queue_and_backpressure_watermark(self):
        async def _run():
            mgr = IngestionQueueManager(maxsize=10, high_watermark_pct=0.7)
            assert mgr.is_backpressure_active is False

            for i in range(7):
                enqueued = await mgr.enqueue(f"log_{i}")
                assert enqueued is True

            assert mgr.is_backpressure_active is True

            # Fill remaining slots
            for i in range(7, 10):
                await mgr.enqueue(f"log_{i}")

            # 11th should be dropped
            overflow = await mgr.enqueue("log_overflow")
            assert overflow is False
            assert mgr.dropped_events_total == 1
        asyncio.run(_run())

