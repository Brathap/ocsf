"""Upgraded Parser Drift Detection, Baseline Monitoring, and Remediation Engine.

Monitors parser health, field extraction degradation, and unparsed token velocity.
Detects when upstream vendors update syslog formats, alerting the SOC and generating
candidate parser proposals to prevent blind data loss.
"""

from typing import Dict, Any, List, Optional
import time


class DriftDetectionEngine:
    def __init__(self, coverage_drop_threshold: float = 0.15):
        self.coverage_drop_threshold = coverage_drop_threshold
        # Parser baselines: parser_id -> {total_events, extracted_fields_count, avg_coverage}
        self.baselines: Dict[str, Dict[str, float]] = {}
        self.recent_windows: Dict[str, List[float]] = {}
        self.alerts: List[Dict[str, Any]] = []

    def record_parsing(self, parser_id: str, expected_fields: int, extracted_fields: int, raw_text: str):
        coverage = extracted_fields / expected_fields if expected_fields > 0 else 1.0

        if parser_id not in self.baselines:
            self.baselines[parser_id] = {
                "sample_count": 1.0,
                "avg_coverage": coverage
            }
            self.recent_windows[parser_id] = [coverage]
            return

        base = self.baselines[parser_id]
        base["sample_count"] += 1.0

        # Maintain baseline during early warm-up or high coverage
        if base["sample_count"] <= 20 or coverage >= base["avg_coverage"]:
            base["avg_coverage"] = (base["avg_coverage"] * 0.9) + (coverage * 0.1)

        # Sliding window for current batch (window size 10)
        win = self.recent_windows[parser_id]
        win.append(coverage)
        if len(win) > 10:
            win.pop(0)

        # Check for significant degradation
        avg_recent = sum(win) / len(win)
        if (base["avg_coverage"] - avg_recent) >= self.coverage_drop_threshold:
            alert = {
                "timestamp": time.time(),
                "parser_id": parser_id,
                "baseline_coverage": round(base["avg_coverage"], 3),
                "current_coverage": round(avg_recent, 3),
                "degradation": round(base["avg_coverage"] - avg_recent, 3),
                "sample_log": raw_text[:200],
                "status": "DRIFT_DETECTED",
                "recommended_action": "Trigger Unknown Source Intelligence candidate pack generation."
            }
            # Limit alerts
            if not self.alerts or (time.time() - self.alerts[-1]["timestamp"] > 5.0):
                self.alerts.append(alert)

    def get_status(self) -> Dict[str, Any]:
        return {
            "active_monitored_parsers": len(self.baselines),
            "total_alerts": len(self.alerts),
            "recent_alerts": self.alerts[-10:],
            "baselines": {k: round(v["avg_coverage"], 3) for k, v in self.baselines.items()}
        }
