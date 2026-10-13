"""Schema Drift & Silent Parsing Failure Monitor for ULPF (Item 6).

Tracks ratio of unmapped / fallback / error records over sliding inspection windows.
Flags alerts when unparsed tokens or structural drift exceed configured thresholds.
"""

import collections
import time
from typing import Any, Dict, List, Optional


class DriftMonitor:
    """Detects schema drift, unmapped attribute spikes, and silent parsing anomalies."""

    def __init__(self, window_size: int = 500, alert_threshold_ratio: float = 0.15):
        self.window_size = window_size
        self.alert_threshold_ratio = alert_threshold_ratio
        self.history: collections.deque = collections.deque(maxlen=window_size)
        self.flags: List[Dict[str, Any]] = []

    def record_inspection(
        self,
        event_id: str,
        source_type: str,
        unmapped_field_count: int,
        parsing_error: bool = False,
        raw_length: int = 0
    ) -> Dict[str, Any]:
        """Record an ingested event's parsing inspection result."""
        entry = {
            "event_id": event_id,
            "source_type": source_type,
            "unmapped_count": unmapped_field_count,
            "parsing_error": parsing_error,
            "raw_length": raw_length,
            "timestamp": time.time(),
        }
        self.history.append(entry)

        # Check if threshold crossed
        stats = self.get_drift_stats()
        if stats["error_or_unmapped_ratio"] >= self.alert_threshold_ratio and len(self.history) >= 20:
            flag = {
                "flag_id": f"drift-alert-{int(time.time()*1000)}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source_type": source_type,
                "severity": "High" if stats["error_or_unmapped_ratio"] > 0.3 else "Medium",
                "ratio": round(stats["error_or_unmapped_ratio"], 4),
                "detail": f"Schema drift detected: {round(stats['error_or_unmapped_ratio']*100, 2)}% of recent logs contain unmapped attributes or fallback parsing."
            }
            if not self.flags or (time.time() - self.history[-1]["timestamp"] < 5 and self.flags[-1]["source_type"] != source_type):
                self.flags.append(flag)
            return flag
        return {}

    def get_drift_stats(self) -> Dict[str, Any]:
        """Calculates drift statistics over the current window."""
        if not self.history:
            return {
                "window_events": 0,
                "unmapped_ratio": 0.0,
                "error_ratio": 0.0,
                "error_or_unmapped_ratio": 0.0,
                "active_flags_count": len(self.flags)
            }

        total = len(self.history)
        unmapped_events = sum(1 for e in self.history if e["unmapped_count"] > 0)
        error_events = sum(1 for e in self.history if e["parsing_error"])
        drift_events = sum(1 for e in self.history if e["unmapped_count"] > 0 or e["parsing_error"])

        return {
            "window_events": total,
            "unmapped_ratio": round(unmapped_events / total, 4),
            "error_ratio": round(error_events / total, 4),
            "error_or_unmapped_ratio": round(drift_events / total, 4),
            "active_flags_count": len(self.flags)
        }

    def get_active_flags(self) -> List[Dict[str, Any]]:
        """Returns list of active drift alerts."""
        return list(self.flags[-20:])

    def clear_flags(self):
        """Clears active flags."""
        self.flags.clear()
