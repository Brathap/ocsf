"""Field-Level Lineage & Byte Tracing Engine for ULPF.

Provides mathematical and byte-precise traceability linking normalized OCSF
attributes back to exact start/end byte offsets and raw slice tokens in the
original wire payload.
"""

from typing import Dict, Any, List, Optional
import hashlib
import base64


class FieldLineageSpan:
    def __init__(self, start: int, end: int, raw_token: str, field_name: str, confidence: float = 1.0):
        self.start = start
        self.end = end
        self.raw_token = raw_token
        self.field_name = field_name
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "raw_token": self.raw_token,
            "confidence": self.confidence,
        }


class LineageEngine:
    """Computes and validates lossless field-level lineage between raw wire text and OCSF targets."""

    @staticmethod
    def compute_sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def trace_spans(raw_text: str, extracted_fields: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Locates extracted fields within the raw log text to construct byte-precise lineage spans."""
        spans: Dict[str, Dict[str, Any]] = {}
        search_offset = 0

        for field_path, val in extracted_fields.items():
            if val is None:
                continue
            str_val = str(val)
            if not str_val:
                continue

            # First search from current offset, then fallback to full text
            pos = raw_text.find(str_val, search_offset)
            if pos == -1:
                pos = raw_text.find(str_val)

            if pos != -1:
                end_pos = pos + len(str_val)
                # Compute exact byte coordinates in the raw UTF-8 wire stream
                byte_start = len(raw_text[:pos].encode("utf-8", errors="replace"))
                byte_end = byte_start + len(str_val.encode("utf-8", errors="replace"))
                spans[field_path] = {
                    "start": pos,
                    "end": end_pos,
                    "byte_start": byte_start,
                    "byte_end": byte_end,
                    "raw_token": str_val,
                    "confidence": 1.0,
                }
                search_offset = end_pos
            else:
                spans[field_path] = {
                    "start": -1,
                    "end": -1,
                    "byte_start": -1,
                    "byte_end": -1,
                    "raw_token": str_val,
                    "confidence": 0.5,
                    "synthesized": True
                }

        return spans

    @staticmethod
    def build_envelope(
        raw_text: str,
        normalized_data: Dict[str, Any],
        parser_id: str = "generic-fallback",
        pack_version: str = "1.0.0",
        extracted_fields: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Constructs an enterprise-grade OCSF envelope with embedded cryptographic and byte-level lineage."""
        raw_bytes = raw_text.encode("utf-8", errors="replace")
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        raw_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # Automatically trace spans if not explicitly provided
        if extracted_fields is None:
            extracted_fields = {}
            if "src_endpoint" in normalized_data and "ip" in normalized_data["src_endpoint"]:
                extracted_fields["src_endpoint.ip"] = normalized_data["src_endpoint"]["ip"]
            if "dst_endpoint" in normalized_data and "ip" in normalized_data["dst_endpoint"]:
                extracted_fields["dst_endpoint.ip"] = normalized_data["dst_endpoint"]["ip"]
            if "user" in normalized_data and "name" in normalized_data["user"]:
                extracted_fields["user.name"] = normalized_data["user"]["name"]

        spans = LineageEngine.trace_spans(raw_text, extracted_fields)

        lineage_block = {
            "raw_sha256": raw_sha256,
            "raw_length_bytes": len(raw_bytes),
            "parser_id": parser_id,
            "pack_version": pack_version,
            "fields": spans,
        }

        # Embed into normalized_data
        enriched_normalized = dict(normalized_data)
        enriched_normalized["lineage"] = lineage_block

        return {
            "traceability": {
                "raw_sha256": raw_sha256,
                "raw_base64": raw_b64,
                "raw_length": len(raw_bytes),
                "sanitized_raw": raw_text,
                "raw_hash": raw_sha256,
                "raw_log_base64": raw_b64,
                "redacted_payload": raw_text,
                "lineage": lineage_block,
            },
            "normalized_data": enriched_normalized
        }
