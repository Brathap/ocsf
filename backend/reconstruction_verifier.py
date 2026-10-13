"""Reconstruction / Round-Trip Verifier for ULPF.

Verifies that parsed/normalized OCSF records can be losslessly reconstructed
back to their original raw bytes according to a reverse-template or parsing rule.
"""

from typing import Dict, Any, Optional, Tuple


def verify_reconstruction(raw_bytes: bytes, parsed_fields: dict, rule: dict) -> dict:
    """Applies rule's reverse-template to parsed_fields to rebuild candidate raw bytes,
    then byte-compares candidate against raw_bytes.

    Returns:
        {
            "verdict": "pass" | "fail",
            "diff": None | "<description of first mismatch: byte offset, expected, actual>"
        }
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8")
        else:
            raw_bytes = bytes(raw_bytes)

    reverse_template = rule.get("reverse_template")
    delimiter = rule.get("delimiter", "")

    # Reconstruct candidate string/bytes
    candidate_bytes = b""
    try:
        if reverse_template:
            # Format using reverse template string: e.g. "{src_ip} -> {dst_ip} : {message}"
            # Safely replace tokens with parsed fields
            candidate_str = reverse_template.format(**parsed_fields)
            candidate_bytes = candidate_str.encode("utf-8")
        elif "fields_order" in rule:
            fields_order = rule["fields_order"]
            parts = [str(parsed_fields.get(f, "")) for f in fields_order]
            candidate_bytes = delimiter.join(parts).encode("utf-8")
        elif "reconstructor" in rule and callable(rule["reconstructor"]):
            candidate = rule["reconstructor"](parsed_fields)
            candidate_bytes = candidate.encode("utf-8") if isinstance(candidate, str) else bytes(candidate)
        else:
            # Fallback direct raw_wire key or unstructured raw payload if present
            candidate = (
                parsed_fields.get("raw_wire")
                or parsed_fields.get("raw_message")
                or parsed_fields.get("unstructured_raw")
                or ""
            )
            candidate_bytes = candidate.encode("utf-8") if isinstance(candidate, str) else bytes(candidate)
    except KeyError as ke:
        return {
            "verdict": "fail",
            "diff": f"Missing required field {str(ke)} to evaluate reverse-template",
        }
    except Exception as e:
        return {
            "verdict": "fail",
            "diff": f"Template reconstruction error: {str(e)}",
        }

    # Byte-by-byte comparison
    if candidate_bytes == raw_bytes:
        return {"verdict": "pass", "diff": None}

    # Find first mismatch
    min_len = min(len(raw_bytes), len(candidate_bytes))
    mismatch_offset = None
    for i in range(min_len):
        if raw_bytes[i] != candidate_bytes[i]:
            mismatch_offset = i
            break

    if mismatch_offset is not None:
        expected_char = chr(raw_bytes[mismatch_offset]) if 32 <= raw_bytes[mismatch_offset] <= 126 else f"\\x{raw_bytes[mismatch_offset]:02x}"
        actual_char = chr(candidate_bytes[mismatch_offset]) if 32 <= candidate_bytes[mismatch_offset] <= 126 else f"\\x{candidate_bytes[mismatch_offset]:02x}"
        diff_desc = (
            f"Mismatch at byte offset {mismatch_offset}: "
            f"expected '{expected_char}' (0x{raw_bytes[mismatch_offset]:02x}), "
            f"got '{actual_char}' (0x{candidate_bytes[mismatch_offset]:02x})"
        )
    else:
        diff_desc = (
            f"Length mismatch: expected {len(raw_bytes)} bytes, "
            f"reconstructed candidate produced {len(candidate_bytes)} bytes "
            f"({'truncated' if len(candidate_bytes) < len(raw_bytes) else 'extended'})"
        )

    return {
        "verdict": "fail",
        "diff": diff_desc,
    }
