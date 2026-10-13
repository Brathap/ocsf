"""Deterministic Unknown Source Intelligence Engine for ULPF.

100% Offline / Air-Gapped. No cloud AI, external LLM, or internet calls required.
Consists of:
1. FormatFingerprinter: Classifies format (CEF, RFC5424, RFC3164, JSON, KV, CSV, Syslog).
2. TemplateClusterer: Drain-like token tree clustering that abstracts dynamic variables (<IP>, <PORT>, <HEX>, <NUM>).
3. FieldInferencer: Deterministic semantic tagging of fields with confidence score and human-readable explanation.
4. ProposalGenerator: Generates draft YAML source packs for operator review.
"""

try:
    import safe_re2 as re2
except ImportError:
    from .. import safe_re2 as re2
re = re2
import json
import yaml
from typing import Dict, Any, List, Optional, Tuple


class FormatFingerprinter:
    """Classifies log formats deterministically based on structural wire signatures."""

    @staticmethod
    def identify(raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        
        # 1. JSON
        if (line.startswith("{") and line.endswith("}")) or (line.startswith("[") and line.endswith("]")):
            try:
                json.loads(line)
                return {"format": "JSON", "confidence": 1.0, "delimiter": None}
            except Exception:
                pass

        # 2. CEF
        if "CEF:" in line:
            return {"format": "CEF", "confidence": 0.98, "delimiter": "|"}

        # 3. LEEF
        if "LEEF:" in line:
            return {"format": "LEEF", "confidence": 0.98, "delimiter": "|"}

        # 4. RFC 5424 Syslog (<PRI>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID ...)
        if re.match(r'^<\d{1,3}>1\s+\d{4}-\d{2}-\d{2}T', line):
            return {"format": "SYSLOG_RFC5424", "confidence": 0.99, "delimiter": " "}

        # 5. RFC 3164 Syslog (<PRI>Mmm dd hh:mm:ss ...)
        if re.match(r'^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
            return {"format": "SYSLOG_RFC3164", "confidence": 0.92, "delimiter": " "}

        # 6. Key-Value (e.g. k1=v1 k2="v2")
        kv_pairs = re.findall(r'([a-zA-Z0-9_\-\.]+)=([^\s"\'=]+|"[^"]*")', line)
        if len(kv_pairs) >= 3:
            return {"format": "KEY_VALUE", "confidence": 0.85, "delimiter": " "}

        # 7. CSV / TSV / Delimited
        if line.count(",") >= 4:
            return {"format": "CSV", "confidence": 0.80, "delimiter": ","}
        if line.count("|") >= 4:
            return {"format": "PIPE_DELIMITED", "confidence": 0.80, "delimiter": "|"}

        return {"format": "UNSTRUCTURED_TEXT", "confidence": 0.50, "delimiter": " "}


class TemplateClusterer:
    """Drain-like deterministic tree clustering that abstracts dynamic variables."""

    VAR_PATTERNS = [
        (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '<IP>'),
        (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), '<IPV6>'),
        (re.compile(r'\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b'), '<MAC>'),
        (re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'), '<TIMESTAMP>'),
        (re.compile(r'\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b'), '<TIMESTAMP>'),
        (re.compile(r'\b[0-9a-fA-F]{32,64}\b'), '<HASH>'),
        (re.compile(r'\b0x[0-9a-fA-F]+\b'), '<HEX>'),
        (re.compile(r'(?<=port\s)\d+|(?<=:)\d{2,5}\b'), '<PORT>'),
        (re.compile(r'\b\d+\b'), '<NUM>'),
    ]

    @classmethod
    def extract_template(cls, raw_line: str) -> str:
        template = raw_line.strip()
        for pattern, token in cls.VAR_PATTERNS:
            template = pattern.sub(token, template)
        return template


class FieldInferencer:
    """Deterministic semantic tagging with confidence and explanation."""

    SEMANTIC_RULES = [
        {
            "field": "src_endpoint.ip",
            "regex": re.compile(r'(?:src(?:_ip)?|from|source|client_ip|actor\.ip)[\s:=]+["\']?((?:\d{1,3}\.){3}\d{1,3})["\']?', re.IGNORECASE),
            "confidence": 0.95,
            "explanation": "Preceded by source identifier prefix and matches valid IPv4 syntax."
        },
        {
            "field": "dst_endpoint.ip",
            "regex": re.compile(r'(?:dst(?:_ip)?|to|destination|srv_ip|server_ip|target\.ip)[\s:=]+["\']?((?:\d{1,3}\.){3}\d{1,3})["\']?', re.IGNORECASE),
            "confidence": 0.95,
            "explanation": "Preceded by destination identifier prefix and matches valid IPv4 syntax."
        },
        {
            "field": "src_endpoint.port",
            "regex": re.compile(r'(?:spt|src_port|sport|s_port)[\s:=]+["\']?(\d{1,5})["\']?', re.IGNORECASE),
            "confidence": 0.90,
            "explanation": "Source port key or suffix matching valid port range."
        },
        {
            "field": "dst_endpoint.port",
            "regex": re.compile(r'(?:dpt|dst_port|dport|d_port)[\s:=]+["\']?(\d{1,5})["\']?', re.IGNORECASE),
            "confidence": 0.90,
            "explanation": "Destination port key or suffix matching valid port range."
        },
        {
            "field": "user.name",
            "regex": re.compile(r'(?:user(?:name)?|usr|login|actor\.user)[\s:=]+["\']?([a-zA-Z0-9_\-\.]+)["\']?', re.IGNORECASE),
            "confidence": 0.88,
            "explanation": "Preceded by user identity prefix."
        },
        {
            "field": "activity_name",
            "regex": re.compile(r'\b(Accepted|Failed|Denied|Blocked|Connected|Disconnected|Teardown|Built|Drop|create)\b', re.IGNORECASE),
            "confidence": 0.85,
            "explanation": "Matches standard security state action keyword."
        },
        {
            "field": "network_protocol",
            "regex": re.compile(r'(?:proto(?:col)?)[\s:=]+["\']?([a-zA-Z]+)["\']?', re.IGNORECASE),
            "confidence": 0.88,
            "explanation": "Identifies transport layer network protocol."
        }
    ]

    @classmethod
    def infer_fields(cls, raw_line: str) -> List[Dict[str, Any]]:
        results = []
        # JSON special-cased extraction if valid JSON
        trimmed = raw_line.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")):
            try:
                data = json.loads(trimmed)
                flattened = {}
                def _flatten(obj, prefix=""):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            _flatten(v, f"{prefix}.{k}" if prefix else k)
                    else:
                        flattened[prefix] = str(obj)
                _flatten(data)
                
                for k, v in flattened.items():
                    k_lower = k.lower()
                    if "src" in k_lower or "actor.ip" in k_lower or "client" in k_lower:
                        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', v):
                            pos = raw_line.find(v)
                            results.append({
                                "ocsf_field": "src_endpoint.ip",
                                "extracted_value": v,
                                "confidence": 0.98,
                                "explanation": f"JSON key '{k}' mapped to source IP",
                                "start": pos if pos != -1 else 0,
                                "end": pos + len(v) if pos != -1 else len(v)
                            })
                    elif "dst" in k_lower or "target.ip" in k_lower or "server" in k_lower:
                        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', v):
                            pos = raw_line.find(v)
                            results.append({
                                "ocsf_field": "dst_endpoint.ip",
                                "extracted_value": v,
                                "confidence": 0.98,
                                "explanation": f"JSON key '{k}' mapped to destination IP",
                                "start": pos if pos != -1 else 0,
                                "end": pos + len(v) if pos != -1 else len(v)
                            })
                    elif "user" in k_lower or "actor.user" in k_lower:
                        pos = raw_line.find(v)
                        results.append({
                            "ocsf_field": "user.name",
                            "extracted_value": v,
                            "confidence": 0.92,
                            "explanation": f"JSON key '{k}' mapped to user name",
                            "start": pos if pos != -1 else 0,
                            "end": pos + len(v) if pos != -1 else len(v)
                        })
                if results:
                    return results
            except Exception:
                pass

        for rule in cls.SEMANTIC_RULES:
            match = rule["regex"].search(raw_line)
            if match:
                val = match.group(1)
                results.append({
                    "ocsf_field": rule["field"],
                    "extracted_value": val,
                    "confidence": rule["confidence"],
                    "explanation": rule["explanation"],
                    "start": match.start(1),
                    "end": match.end(1)
                })
        return results


class ProposalGenerator:
    """Generates an air-gapped YAML candidate source pack from unknown logs."""

    @staticmethod
    def generate_candidate_pack(vendor: str, product: str, sample_logs: List[str]) -> str:
        if not sample_logs:
            return ""

        first_log = sample_logs[0]
        fingerprint = FormatFingerprinter.identify(first_log)
        template = TemplateClusterer.extract_template(first_log)
        inferred = FieldInferencer.infer_fields(first_log)

        # Generate robust regex capturing tokens with unique group names
        # Handle multiple occurrences of IP, NUM, TIMESTAMP
        regex_pattern = template
        tokens_map = [
            ('<TIMESTAMP>', r'(?P<timestamp>\S+)'),
            ('<IP>', r'(?P<src_ip>[0-9.]+)', r'(?P<dst_ip>[0-9.]+)'),
            ('<NUM>', r'(?P<src_port>\d+)', r'(?P<dst_port>\d+)'),
        ]
        
        # Split tokens, escape static text, and keep groups
        pattern_parts = []
        token_regex = re.compile(r'(<TIMESTAMP>|<IP>|<NUM>|<PORT>|<HEX>|<MAC>|<HASH>)')
        pieces = token_regex.split(template)
        
        counts = {"<TIMESTAMP>": 0, "<IP>": 0, "<NUM>": 0}
        for piece in pieces:
            if piece == "<TIMESTAMP>":
                counts["<TIMESTAMP>"] += 1
                pattern_parts.append(r'(?P<timestamp>\S+)')
            elif piece == "<IP>":
                counts["<IP>"] += 1
                if counts["<IP>"] == 1:
                    pattern_parts.append(r'(?P<src_ip>[0-9.]+)')
                elif counts["<IP>"] == 2:
                    pattern_parts.append(r'(?P<dst_ip>[0-9.]+)')
                else:
                    pattern_parts.append(r'[0-9.]+')
            elif piece == "<NUM>":
                counts["<NUM>"] += 1
                if counts["<NUM>"] == 1:
                    pattern_parts.append(r'(?P<src_port>\d+)')
                elif counts["<NUM>"] == 2:
                    pattern_parts.append(r'(?P<dst_port>\d+)')
                else:
                    pattern_parts.append(r'\d+')
            elif piece in ["<PORT>", "<HEX>", "<MAC>", "<HASH>"]:
                pattern_parts.append(r'\S+')
            else:
                pattern_parts.append(re.escape(piece))
        
        regex_pattern = "".join(pattern_parts)


        mappings = {
            "src_endpoint.ip": "src_ip",
            "dst_endpoint.ip": "dst_ip",
            "src_endpoint.port": "src_port",
            "dst_endpoint.port": "dst_port",
        }

        candidate_data = {
            "metadata": {
                "vendor": vendor,
                "product": product,
                "version": "1.0.0-draft",
                "priority": 90,
                "format_detected": fingerprint.get("format", "UNSTRUCTURED_TEXT"),
                "clustering_template": template
            },
            "detection": {
                "match_regex": [re.escape(first_log[:25])]
            },
            "parser": {
                "type": "regex",
                "pattern": regex_pattern
            },
            "ocsf": {
                "class_uid": 4001,
                "category_name": "Network Activity",
                "activity_name": "Inferred Network Telemetry"
            },
            "mappings": mappings
        }

        header = "# Proposed Candidate Source Pack (Generated 100% Offline)\n"
        return header + yaml.safe_dump(candidate_data, sort_keys=False)


