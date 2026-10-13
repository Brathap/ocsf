"""Threat Intelligence Management & Offline Manifest Verification Engine for ULPF (SIH 26156).

Features:
- Versioned threat intelligence store with ISO timestamps, version IDs, and record counts.
- Offline import workflow with SHA-256 manifest verification:
  - Expects a manifest dict/JSON containing {"version": str, "sha256": str, "timestamp": str}
  - Rejects imports if the computed SHA-256 of the CSV data does not match the manifest.
  - Rejects imports if required columns (src_ip, threat_group, severity, mitre_id) are missing.
- Audits every threat intel import (success or rejection) into the audit trail.
- Surfaces metadata: version, last_updated, sha256, total_iocs for the SOC console.
"""

import csv
import datetime
import hashlib
import io
import json
import os
import shutil
from typing import Any, Dict, List, Optional, Tuple


class ThreatIntelManager:
    def __init__(self, csv_path: str, manifest_path: Optional[str] = None, audit_callback=None):
        self.csv_path = os.path.abspath(csv_path)
        self.manifest_path = os.path.abspath(manifest_path or (self.csv_path + ".manifest.json"))
        self.audit_callback = audit_callback
        self.intel_cache: Dict[str, Dict[str, str]] = {}
        self.version = "1.0.0"
        self.last_updated = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.sha256 = ""

        self.load_intel()

    def _compute_sha256(self, content_bytes: bytes) -> str:
        return hashlib.sha256(content_bytes).hexdigest()

    def load_intel(self) -> Dict[str, Any]:
        """Loads and indexes the CSV file, loading or initializing the manifest."""
        self.intel_cache.clear()

        # Load manifest if available
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as mf:
                    mdata = json.load(mf)
                    self.version = mdata.get("version", "1.0.0")
                    self.last_updated = mdata.get("last_updated", self.last_updated)
            except Exception as e:
                print(f"[THREAT INTEL] Manifest read warning: {e}")

        if os.path.exists(self.csv_path):
            with open(self.csv_path, "rb") as f:
                content = f.read()
            self.sha256 = self._compute_sha256(content)

            try:
                text = content.decode("utf-8")
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    ip = row.get("src_ip", "").strip()
                    if ip:
                        self.intel_cache[ip] = {
                            "threat_group": row.get("threat_group", "Unknown"),
                            "severity": row.get("severity", "High"),
                            "mitre_id": row.get("mitre_id", "T1078"),
                        }
            except Exception as e:
                print(f"[THREAT INTEL] Error parsing CSV: {e}")

        # If manifest didn't exist, create it initially
        if not os.path.exists(self.manifest_path) and os.path.exists(self.csv_path):
            self._save_manifest()

        return self.get_metadata()

    def _save_manifest(self):
        mdata = {
            "version": self.version,
            "last_updated": self.last_updated,
            "sha256": self.sha256,
            "total_iocs": len(self.intel_cache),
        }
        with open(self.manifest_path, "w", encoding="utf-8") as mf:
            json.dump(mdata, mf, indent=2)

    def import_threat_intel(
        self,
        csv_bytes: bytes,
        manifest: Dict[str, Any],
        actor_username: str = "admin",
        actor_role: str = "admin"
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Imports an updated threat intel CSV with strict checksum manifest verification."""
        expected_sha = (manifest.get("sha256") or "").strip().lower()
        new_version = (manifest.get("version") or "").strip()

        if not expected_sha or not new_version:
            err_msg = "Invalid manifest: 'sha256' and 'version' fields are mandatory."
            if self.audit_callback:
                self.audit_callback(actor_username, actor_role, "THREAT_INTEL_IMPORT_REJECTED", "threat_intel.csv", 400, err_msg)
            return False, err_msg, self.get_metadata()

        computed_sha = self._compute_sha256(csv_bytes).lower()
        if computed_sha != expected_sha:
            err_msg = f"Checksum mismatch: manifest expected {expected_sha}, but received content hash {computed_sha}"
            if self.audit_callback:
                self.audit_callback(actor_username, actor_role, "THREAT_INTEL_IMPORT_REJECTED", "threat_intel.csv", 400, err_msg)
            return False, err_msg, self.get_metadata()

        # Validate CSV structure and headers
        try:
            text = csv_bytes.decode("utf-8")
            reader = csv.DictReader(io.StringIO(text))
            fieldnames = set(reader.fieldnames or [])
            required = {"src_ip", "threat_group", "severity", "mitre_id"}
            if not required.issubset(fieldnames):
                err_msg = f"CSV missing required columns: {required - fieldnames}"
                if self.audit_callback:
                    self.audit_callback(actor_username, actor_role, "THREAT_INTEL_IMPORT_REJECTED", "threat_intel.csv", 400, err_msg)
                return False, err_msg, self.get_metadata()

            # Parse and verify records
            new_cache = {}
            for row in reader:
                ip = row.get("src_ip", "").strip()
                if ip:
                    new_cache[ip] = {
                        "threat_group": row.get("threat_group", "Unknown"),
                        "severity": row.get("severity", "High"),
                        "mitre_id": row.get("mitre_id", "T1078"),
                    }
        except Exception as e:
            err_msg = f"Failed to parse CSV: {e}"
            if self.audit_callback:
                self.audit_callback(actor_username, actor_role, "THREAT_INTEL_IMPORT_REJECTED", "threat_intel.csv", 400, err_msg)
            return False, err_msg, self.get_metadata()

        # Atomically write to CSV and manifest
        temp_csv = self.csv_path + ".tmp"
        with open(temp_csv, "wb") as f:
            f.write(csv_bytes)
        shutil.move(temp_csv, self.csv_path)

        self.intel_cache = new_cache
        self.version = new_version
        self.sha256 = computed_sha
        self.last_updated = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._save_manifest()

        success_msg = f"Threat intelligence successfully upgraded to version {self.version} ({len(new_cache)} IOCs)."
        if self.audit_callback:
            self.audit_callback(actor_username, actor_role, "THREAT_INTEL_UPDATED", "threat_intel.csv", 200, success_msg)

        return True, success_msg, self.get_metadata()

    def is_stale(self, max_days: int = 14) -> bool:
        """Determines if the local threat intel database exceeds max acceptable freshness threshold."""
        try:
            ts = self.last_updated.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(ts)
            now = datetime.datetime.now(datetime.timezone.utc)
            return (now - dt).total_seconds() > (max_days * 86400)
        except Exception:
            return False

    def get_metadata(self) -> Dict[str, Any]:
        stale = self.is_stale(max_days=14)
        return {
            "version": self.version,
            "last_updated": self.last_updated,
            "sha256": self.sha256,
            "total_iocs": len(self.intel_cache),
            "is_stale": stale,
            "freshness_status": "STALE_ATTENTION_REQUIRED" if stale else "FRESH_ACTIVE",
        }

    def match_ip(self, ip: str) -> Optional[Dict[str, str]]:
        return self.intel_cache.get(ip)
