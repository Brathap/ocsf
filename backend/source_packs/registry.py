"""Declarative Source Pack Schema, Loader, Validator, and Runtime Registry.

Permits air-gapped, zero-downtime hot-reloading of vendor parsing rules from YAML.
Includes rigorous regex/CEF/KV pattern compilation, test assertions, and fallback safety.
"""

import os
try:
    import safe_re2 as re2
except ImportError:
    from .. import safe_re2 as re2
re = re2
import yaml
import glob
from typing import Dict, Any, List, Optional, Tuple


class SourcePackValidationError(Exception):
    pass


class SourcePack:
    """Represents a compiled, declarative vendor log parser."""

    def __init__(self, pack_data: Dict[str, Any], filepath: str = ""):
        self.raw_data = pack_data
        self.filepath = filepath
        self._validate()

        self.vendor = pack_data["metadata"]["vendor"]
        self.product = pack_data["metadata"]["product"]
        self.version = pack_data["metadata"]["version"]
        self.pack_id = f"{self.vendor}_{self.product}_{self.version}".lower().replace(" ", "_")
        self.priority = int(pack_data["metadata"].get("priority", 100))
        self.ocsf_class_uid = int(pack_data.get("ocsf", {}).get("class_uid", 6001))
        self.category_name = pack_data.get("ocsf", {}).get("category_name", "Application Activity")
        self.activity_name = pack_data.get("ocsf", {}).get("activity_name", "Log Ingestion")

        # Compile detection matchers
        self.detection_patterns: List[re.Pattern] = []
        for pat in pack_data.get("detection", {}).get("match_regex", []):
            self.detection_patterns.append(re.compile(pat))

        # Compile extraction rules
        self.parser_type = pack_data.get("parser", {}).get("type", "regex")
        self.extract_regex: Optional[re.Pattern] = None
        if self.parser_type == "regex" and "pattern" in pack_data.get("parser", {}):
            self.extract_regex = re.compile(pack_data["parser"]["pattern"])

        self.mappings = pack_data.get("mappings", {})

    def _validate(self):
        meta = self.raw_data.get("metadata", {})
        if not meta.get("vendor") or not meta.get("product") or not meta.get("version"):
            raise SourcePackValidationError("Pack metadata requires vendor, product, and version.")
        if "detection" not in self.raw_data:
            raise SourcePackValidationError("Pack requires detection configuration.")

    def matches(self, raw_line: str) -> bool:
        """Determines if this pack is suited for the incoming raw log."""
        if not self.detection_patterns:
            return False
        return any(p.search(raw_line) for p in self.detection_patterns)

    def parse(self, raw_line: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Parses raw text into an extracted dict and OCSF mapping."""
        extracted: Dict[str, Any] = {}

        if self.parser_type == "regex" and self.extract_regex:
            match = self.extract_regex.search(raw_line)
            if not match:
                return None
            extracted = match.groupdict()

        elif self.parser_type == "cef":
            # Native high-speed CEF parser
            if not raw_line.startswith("CEF:") and " CEF:" not in raw_line:
                return None
            cef_part = raw_line[raw_line.find("CEF:"):]
            parts = cef_part.split("|")
            if len(parts) >= 8:
                extracted["cef_version"] = parts[0]
                extracted["device_vendor"] = parts[1]
                extracted["device_product"] = parts[2]
                extracted["device_version"] = parts[3]
                extracted["device_event_class_id"] = parts[4]
                extracted["name"] = parts[5]
                extracted["severity"] = parts[6]
                extension_str = "|".join(parts[7:])
                # Parse key=value pairs using linear-time re2 compatible pattern
                kv_matches = re.findall(r'(\w+)=("[^"]*"|\'[^\']*\'|[^\s=]+)', extension_str)
                for k, v in kv_matches:
                    clean_v = v.strip("\"'")
                    extracted[k] = clean_v

        elif self.parser_type == "json":
            try:
                import safe_serializer as json_engine
            except ImportError:
                from .. import safe_serializer as json_engine
            try:
                extracted = json_engine.loads(raw_line)
            except Exception:
                return None

        elif self.parser_type == "kv":
            # High-speed key=value parser (e.g. FortiGate, Checkpoint, SonicWall)
            kv_matches = re.findall(r'([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|\'([^\']*)\'|([^=|\s;,]+))', raw_line)
            for k, q1, q2, bare in kv_matches:
                v = q1 or q2 or bare
                extracted[k] = v
            if not extracted:
                return None

        elif self.parser_type == "leef":
            # Log Event Extended Format (LEEF) parser (LEEF:1.0|Vendor|Product|Version|EventID|delimiter|...)
            if "LEEF:" not in raw_line:
                return None
            leef_part = raw_line[raw_line.find("LEEF:"):]
            parts = leef_part.split("|")
            if len(parts) >= 5:
                extracted["leef_version"] = parts[0]
                extracted["device_vendor"] = parts[1]
                extracted["device_product"] = parts[2]
                extracted["device_version"] = parts[3]
                extracted["device_event_class_id"] = parts[4]
                delimiter = "\t"
                attrs_str = ""
                if len(parts) >= 6:
                    # delimiter might be specified in header or default tab/whitespace
                    if len(parts) >= 7 and len(parts[5]) <= 2:
                        delimiter = parts[5]
                        attrs_str = "|".join(parts[6:])
                    else:
                        attrs_str = "|".join(parts[5:])
                # parse attributes by delimiter or regex
                kv_matches = re.findall(r'([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|([^' + re.escape(delimiter) + r'=\s]+))', attrs_str)
                for k, q1, bare in kv_matches:
                    extracted[k] = q1 or bare

        elif self.parser_type == "tsv":
            # Tab-separated values with dynamic headers (e.g. Zeek TSV logs)
            fields_header = self.raw_data.get("parser", {}).get("fields", [])
            cols = raw_line.strip().split("\t")
            if len(cols) == len(fields_header):
                for f_name, f_val in zip(fields_header, cols):
                    if f_val != "-":
                        extracted[f_name] = f_val

        # Build normalized OCSF dictionary
        ocsf_out: Dict[str, Any] = {
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "vendor_name": self.vendor,
                    "name": self.product,
                    "version": self.version
                },
                "trust_score": 100,
                "provenance": f"source_pack:{self.pack_id}"
            },
            "class_uid": self.ocsf_class_uid,
            "category_name": self.category_name,
            "activity_name": self.activity_name,
            "severity_id": int(extracted.get("severity_id", 1)),
            "severity": extracted.get("severity", "Informational"),
        }

        # Apply field mappings and track mapped source fields
        mapped_src_fields = set()
        for target_field, src_field in self.mappings.items():
            if src_field in extracted:
                mapped_src_fields.add(src_field)
                val = extracted[src_field]
                # Dot notation assignment
                parts = target_field.split(".")
                curr = ocsf_out
                for p in parts[:-1]:
                    if p not in curr:
                        curr[p] = {}
                    curr = curr[p]
                curr[parts[-1]] = val

        # Retain all unmapped source-specific fields under unmapped
        unmapped = {k: v for k, v in extracted.items() if k not in mapped_src_fields}
        ocsf_out["unmapped"] = unmapped

        return extracted, ocsf_out



class SourcePackRegistry:
    """Thread-safe, air-gapped registry for declarative source packs with hot reload."""

    def __init__(self, packs_dir: str):
        self.packs_dir = packs_dir
        self.packs: Dict[str, SourcePack] = {}
        self.reload()

    def reload(self) -> int:
        """Discovers, validates, and reloads all source packs in the directory tree."""
        new_packs: Dict[str, SourcePack] = {}
        if not os.path.isdir(self.packs_dir):
            os.makedirs(self.packs_dir, exist_ok=True)
            return 0

        yaml_files = glob.glob(os.path.join(self.packs_dir, "**", "*.yaml"), recursive=True) + \
                     glob.glob(os.path.join(self.packs_dir, "**", "*.yml"), recursive=True)

        for yf in yaml_files:
            try:
                with open(yf, "r", encoding="utf-8") as f:
                    docs = yaml.safe_load_all(f)
                    for data in docs:
                        if not data:
                            continue
                        pack = SourcePack(data, filepath=yf)
                        new_packs[pack.pack_id] = pack
            except Exception as e:
                # Log or skip invalid pack without bringing down the system
                continue

        self.packs = new_packs
        return len(self.packs)

    def route_and_parse(self, raw_line: str) -> Optional[Tuple[SourcePack, Dict[str, Any], Dict[str, Any]]]:
        """Routes a log to the highest priority matching pack and parses it."""
        sorted_packs = sorted(self.packs.values(), key=lambda p: p.priority, reverse=True)
        for pack in sorted_packs:
            if pack.matches(raw_line):
                res = pack.parse(raw_line)
                if res:
                    extracted, ocsf = res
                    return pack, extracted, ocsf
        return None

    @staticmethod
    def normalize_timestamp(
        raw_ts: Optional[str] = None,
        source_tz_offset_hours: float = 0.0,
        ingest_datetime: Optional[Any] = None
    ) -> str:
        """Normalizes timestamps into UTC ISO-8601 (YYYY-MM-DDTHH:MM:SS.fZ).

        Requirements (Point 8):
        - Defaults to UTC ISO-8601.
        - If an RFC 3164 timestamp lacks year or timezone (e.g. 'Oct 13 12:45:00'),
          infers current year from ingestion time and applies configurable source timezone fallback.
        """
        import datetime
        now_dt = ingest_datetime or datetime.datetime.now(datetime.timezone.utc)
        if not raw_ts or not isinstance(raw_ts, str) or not raw_ts.strip():
            return now_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        raw_str = raw_ts.strip()

        # 1. Check if already ISO-8601
        try:
            if "T" in raw_str:
                clean_iso = raw_str.replace("Z", "+00:00")
                parsed_dt = datetime.datetime.fromisoformat(clean_iso)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=datetime.timezone.utc)
                utc_dt = parsed_dt.astimezone(datetime.timezone.utc)
                return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            pass

        # 2. Check if Unix epoch timestamp (seconds or milliseconds)
        try:
            val = float(raw_str)
            if val > 1e11:  # milliseconds
                val = val / 1000.0
            dt = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            pass

        # 3. RFC 3164 Syslog timestamp: e.g. "Oct 13 12:45:00" or "Oct  5 09:12:34"
        import re as std_re
        m = std_re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$', raw_str)
        if m:
            month_str, day_str, hour_str, min_str, sec_str = m.groups()
            months = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                      "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
            month_num = months.get(month_str, now_dt.month)
            # Infer year from ingestion datetime
            year = now_dt.year
            # Apply source timezone offset fallback
            src_tz = datetime.timezone(datetime.timedelta(hours=source_tz_offset_hours))
            parsed_dt = datetime.datetime(
                year=year,
                month=month_num,
                day=int(day_str),
                hour=int(hour_str),
                minute=int(min_str),
                second=int(sec_str),
                tzinfo=src_tz
            )
            utc_dt = parsed_dt.astimezone(datetime.timezone.utc)
            return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return now_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def create_fallback_base_event(raw_line: str, source_ip: Optional[str] = None, timestamp: Optional[str] = None) -> Dict[str, Any]:
        """Creates an OCSF v1.1.0 BaseEvent for unparsed logs requiring review.

        Enterprise defense against unparsed blind spots:
        - Never drops telemetry to raw text files.
        - Preserves raw payload inside BaseEvent OCSF schema.
        - Extracts or assigns ingestion timestamp and source IP.
        - Tags status as 'unparsed_requires_review'.
        """
        import datetime
        now_iso = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        src_ip = source_ip
        if not src_ip:
            # Attempt to extract candidate IP from payload
            ip_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_line)
            src_ip = ip_candidates[0] if ip_candidates else "0.0.0.0"

        return {
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "vendor_name": "Generic",
                    "name": "ULPF Ingestion Engine",
                    "version": "1.1.0"
                },
                "trust_score": 50,
                "provenance": "fallback:unparsed_raw"
            },
            "class_uid": 6001,
            "category_name": "Application Activity",
            "activity_name": "Unparsed System Event",
            "severity_id": 2,
            "severity": "Low",
            "status": "unparsed_requires_review",
            "time": now_iso,
            "src_endpoint": {
                "ip": src_ip
            },
            "unmapped": {
                "raw_payload": raw_line
            }
        }

    def route_and_parse_with_fallback(
        self, raw_line: str, source_ip: Optional[str] = None, timestamp: Optional[str] = None
    ) -> Tuple[Optional[SourcePack], Dict[str, Any], Dict[str, Any]]:
        """Routes to active packs; if no parser matches, returns fallback BaseEvent OCSF v1.1.0."""
        routed = self.route_and_parse(raw_line)
        if routed is not None:
            return routed
        fallback_event = self.create_fallback_base_event(raw_line, source_ip=source_ip, timestamp=timestamp)
        return None, {"raw_payload": raw_line, "src_ip": fallback_event["src_endpoint"]["ip"]}, fallback_event

