"""Named Entity PII Redaction Engine with Verhoeff Validation for ULPF (SIH 26156).

Entities handled:
1. Aadhaar (UIDAI 12-digit number):
   - Format: 12 continuous digits or 4-4-4 separated by spaces or hyphens.
   - Algorithmic check: Verhoeff checksum algorithm (multiplication table d, permutation table p, inverse table inv).
   - Prevents false-positives on 12-digit timestamps, order IDs, sequence numbers, unix epoch millis.
2. PAN (Permanent Account Number - Income Tax Dept of India):
   - Format: [A-Z]{5}[0-9]{4}[A-Z]{1} (e.g., ABCDE1234F).
3. Indian Mobile Numbers:
   - Format: Valid 10-digit mobile starting with 6, 7, 8, or 9, optionally prefixed with +91, 91, or 0.
4. Email Addresses:
   - Standard RFC 5322 simplified email regex pattern.
5. IMEI (International Mobile Equipment Identity):
   - Format: 15-digit decimal number validated with Luhn algorithm.

Compliance Output:
- compliance.pii_redacted: bool
- compliance.pii_redacted_types: list of str (e.g. ["aadhaar", "pan", "email"])
"""

import safe_re2 as re2
re = re2
from typing import List, Tuple

# ------------------------------------------------------------------------------
# VERHOEFF ALGORITHM TABLES FOR AADHAAR CHECKSUM
# ------------------------------------------------------------------------------
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """Validates that a string of digits passes the Verhoeff checksum algorithm."""
    if not num_str.isdigit():
        return False
    c = 0
    # Process digits in reverse order
    reversed_digits = [int(d) for d in reversed(num_str)]
    for i, digit in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


def generate_verhoeff_checksum(num_str: str) -> str:
    """Computes the Verhoeff check digit for an 11-digit base string."""
    c = 0
    reversed_digits = [int(d) for d in reversed(num_str)]
    for i, digit in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][digit]]
    return str(_VERHOEFF_INV[c])


def validate_luhn(num_str: str) -> bool:
    """Validates a 15-digit IMEI number with Luhn algorithm."""
    if not num_str.isdigit() or len(num_str) != 15:
        return False
    total = 0
    reverse_digits = [int(d) for d in reversed(num_str)]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d
    return total % 10 == 0


# Pre-compiled Regex Patterns with word-boundaries
AADHAAR_CANDIDATE_REGEX = re.compile(r"(?<!\d)(\d{4})[ -]?(\d{4})[ -]?(\d{4})(?!\d)")
PAN_REGEX = re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b")
# Indian mobile: exactly 10 digits starting with 6-9, preceded by word boundary or optional +91/91/0
INDIAN_MOBILE_REGEX = re.compile(r"(?<!\d)(?:(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9})(?!\d)")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
IMEI_CANDIDATE_REGEX = re.compile(r"(?<!\d)\d{15}(?!\d)")


# Zero-width spaces, soft hyphens, and invisible formatting separators used to evade detection
ZERO_WIDTH_CHARS_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u00AD\u2060]")

def redact_pii(text: str) -> Tuple[str, List[str]]:
    """Sanitizes text by redacting named entities while preventing false positives.

    Returns:
        (sanitized_text, list_of_redacted_entity_types)
    """
    if not text:
        return text, []

    redacted_types = []
    # Strip zero-width evasion characters while preserving layout
    sanitized = ZERO_WIDTH_CHARS_REGEX.sub("", text)

    # 1. Aadhaar Redaction with Verhoeff Validation
    def aadhaar_sub(match):
        raw_digits = match.group(1) + match.group(2) + match.group(3)
        # First digit of valid Aadhaar cannot be 0 or 1 according to UIDAI specification
        if raw_digits[0] in ("0", "1"):
            return match.group(0)

        if validate_verhoeff(raw_digits):
            if "aadhaar" not in redacted_types:
                redacted_types.append("aadhaar")
            return "[REDACTED_AADHAAR]"
        return match.group(0)

    sanitized = AADHAAR_CANDIDATE_REGEX.sub(aadhaar_sub, sanitized)

    # 2. PAN Card Redaction (5 letters + 4 digits + 1 letter)
    def pan_sub(match):
        pan = match.group(1)
        if "pan" not in redacted_types:
            redacted_types.append("pan")
        return "[REDACTED_PAN]"

    sanitized = PAN_REGEX.sub(pan_sub, sanitized)

    # 3. Email Address Redaction
    if EMAIL_REGEX.search(sanitized):
        if "email" not in redacted_types:
            redacted_types.append("email")
        sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized)

    # 4. Indian Mobile Number Redaction
    def mobile_sub(match):
        raw_match = match.group(0)
        digits = re.sub(r"\D", "", raw_match)
        if len(digits) == 10 and digits[0] in "6789":
            if "mobile" not in redacted_types:
                redacted_types.append("mobile")
            return "[REDACTED_MOBILE]"
        elif len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
            if "mobile" not in redacted_types:
                redacted_types.append("mobile")
            return "[REDACTED_MOBILE]"
        elif len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
            if "mobile" not in redacted_types:
                redacted_types.append("mobile")
            return "[REDACTED_MOBILE]"
        return raw_match

    sanitized = INDIAN_MOBILE_REGEX.sub(mobile_sub, sanitized)

    # 5. IMEI Redaction with Luhn Validation
    def imei_sub(match):
        imei = match.group(0)
        if validate_luhn(imei):
            if "imei" not in redacted_types:
                redacted_types.append("imei")
            return "[REDACTED_IMEI]"
        return imei

    sanitized = IMEI_CANDIDATE_REGEX.sub(imei_sub, sanitized)

    return sanitized, redacted_types
