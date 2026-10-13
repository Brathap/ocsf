"""Tests for Named Entity PII Redaction Coverage (Requirement 3).

Verifies:
1. Aadhaar numbers with valid Verhoeff checksums ARE redacted.
2. False-positive non-Aadhaar numbers (12-digit timestamps, order IDs, invalid Verhoeff checksums) ARE NOT redacted.
3. PAN numbers (e.g. ABCDE1234F) ARE redacted as [REDACTED_PAN].
4. Indian mobile numbers (+91, 0, or 10-digit) ARE redacted as [REDACTED_MOBILE].
5. Email addresses ARE redacted as [REDACTED_EMAIL].
6. 15-digit IMEI numbers with valid Luhn checksum ARE redacted as [REDACTED_IMEI].
7. pii_redacted_types accurately tags all matched entity categories.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from pii_redactor import redact_pii, validate_verhoeff, generate_verhoeff_checksum, validate_luhn


class TestPIIRedactionCoverage(unittest.TestCase):
    def test_verhoeff_checksum_algorithm(self):
        """Validate Verhoeff checksum calculations with known numbers."""
        # 11 digits: "23456789012" -> check digit
        base = "23456789012"
        check_digit = generate_verhoeff_checksum(base)
        valid_aadhaar = base + check_digit
        self.assertTrue(validate_verhoeff(valid_aadhaar))

        # Tampered digit fails
        tampered = valid_aadhaar[:-1] + str((int(valid_aadhaar[-1]) + 1) % 10)
        self.assertFalse(validate_verhoeff(tampered))

    def test_aadhaar_true_positive_redaction(self):
        """Valid Aadhaar with Verhoeff checksum is sanitized."""
        # Generate 2 valid Aadhaar numbers
        aadhaar_1 = "98234512908" + generate_verhoeff_checksum("98234512908")
        aadhaar_2 = "45217890234" + generate_verhoeff_checksum("45217890234")
        
        # Test 12-digit continuous and 4-4-4 space-separated
        formatted_2 = f"{aadhaar_2[:4]} {aadhaar_2[4:8]} {aadhaar_2[8:]}"

        text = f"User KYC verification aadhaar={aadhaar_1} second_ref={formatted_2}"
        sanitized, entity_types = redact_pii(text)

        self.assertNotIn(aadhaar_1, sanitized)
        self.assertNotIn(aadhaar_2, sanitized)
        self.assertIn("[REDACTED_AADHAAR]", sanitized)
        self.assertIn("aadhaar", entity_types)
        self.assertEqual(sanitized.count("[REDACTED_AADHAAR]"), 2)

    def test_aadhaar_false_positive_prevention(self):
        """Known false positives (12-digit epoch ms, order numbers, timestamps) must NOT be redacted."""
        # A 12-digit timestamp or order ID with invalid Verhoeff checksum
        timestamp_ms = "172734567890"  # Arbitrary 12-digit timestamp
        if validate_verhoeff(timestamp_ms):
            timestamp_ms = "172734567891"

        order_id = "998877665544"
        if validate_verhoeff(order_id):
            order_id = "998877665543"

        text = f"Order status order_id={order_id} server_ts={timestamp_ms} status=SUCCESS"
        sanitized, entity_types = redact_pii(text)

        self.assertEqual(sanitized, text, "Non-Aadhaar 12-digit IDs must NOT be redacted")
        self.assertNotIn("aadhaar", entity_types)

    def test_pan_card_redaction(self):
        """Permanent Account Number (PAN) 5 letters + 4 digits + 1 letter."""
        text = "Tax payment received for PAN ABCDE1234F ref=TX9982"
        sanitized, entity_types = redact_pii(text)

        self.assertNotIn("ABCDE1234F", sanitized)
        self.assertIn("[REDACTED_PAN]", sanitized)
        self.assertIn("pan", entity_types)

    def test_indian_mobile_redaction(self):
        """Indian 10-digit mobile with +91 or raw 98/99/88/77 prefix."""
        text = "Contact user at +91 9876543210 or alternate 08123456789"
        sanitized, entity_types = redact_pii(text)

        self.assertNotIn("9876543210", sanitized)
        self.assertNotIn("8123456789", sanitized)
        self.assertIn("[REDACTED_MOBILE]", sanitized)
        self.assertIn("mobile", entity_types)

    def test_email_redaction(self):
        """Standard email addresses."""
        text = "Escalate incident to secops-lead@defence.gov.in and analyst.1@cert-in.org.in"
        sanitized, entity_types = redact_pii(text)

        self.assertNotIn("secops-lead@defence.gov.in", sanitized)
        self.assertNotIn("analyst.1@cert-in.org.in", sanitized)
        self.assertIn("[REDACTED_EMAIL]", sanitized)
        self.assertIn("email", entity_types)

    def test_imei_redaction(self):
        """15-digit IMEI validated with Luhn."""
        # Valid Luhn 15-digit IMEI
        valid_imei = "862740041234564"
        if not validate_luhn(valid_imei):
            # Construct a valid Luhn 15-digit number
            base14 = "86274004123456"
            total = 0
            for idx, d in enumerate(reversed([int(x) for x in base14])):
                # when 15th digit is appended, base14 digits shift parity
                val = int(d)
                if idx % 2 == 0:  # second from right in 15 digits
                    doubled = val * 2
                    total += (doubled - 9) if doubled > 9 else doubled
                else:
                    total += val
            check = (10 - (total % 10)) % 10
            valid_imei = base14 + str(check)

        self.assertTrue(validate_luhn(valid_imei))

        text = f"Endpoint registration device_imei={valid_imei} state=ACTIVE"
        sanitized, entity_types = redact_pii(text)

        self.assertNotIn(valid_imei, sanitized)
        self.assertIn("[REDACTED_IMEI]", sanitized)
        self.assertIn("imei", entity_types)

    def test_multi_entity_type_tagging(self):
        """Multiple PII entities present simultaneously in one log line."""
        aadhaar = "98234512908" + generate_verhoeff_checksum("98234512908")
        text = (
            f"KYC submission: citizen_aadhaar={aadhaar}, pan=BNZPA1234K, "
            f"phone=+91-9988776655, email=officer@ntro.gov.in"
        )
        sanitized, entity_types = redact_pii(text)

        self.assertIn("aadhaar", entity_types)
        self.assertIn("pan", entity_types)
        self.assertIn("mobile", entity_types)
        self.assertIn("email", entity_types)
        self.assertEqual(len(entity_types), 4)

    def test_zero_width_character_evasion_defeated(self):
        """Confirm adversarial zero-width and invisible unicode insertions cannot evade redaction."""
        aadhaar = "98234512908" + generate_verhoeff_checksum("98234512908")
        obfuscated_aadhaar = f"{aadhaar[:4]}\u200b{aadhaar[4:8]}\u200c{aadhaar[8:]}"
        text = f"Audit log: target_aadhaar={obfuscated_aadhaar}"
        sanitized, entity_types = redact_pii(text)
        self.assertIn("aadhaar", entity_types)
        self.assertIn("[REDACTED_AADHAAR]", sanitized)


if __name__ == "__main__":
    unittest.main()
