"""Unit and Integration Tests for Byte-Level Reconstruction Verifier (Item 3).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from reconstruction_verifier import verify_reconstruction


class TestReconstructionVerifier(unittest.TestCase):
    def test_reconstruction_pass_exact_match(self):
        """Test that an accurate reverse template reproduces the exact raw bytes with verdict == 'pass'."""
        raw_wire = "SRC=198.51.100.23 DST=10.0.0.1 PROTO=TCP DPT=443"
        raw_bytes = raw_wire.encode("utf-8")

        parsed_fields = {
            "src_ip": "198.51.100.23",
            "dst_ip": "10.0.0.1",
            "proto": "TCP",
            "port": "443"
        }

        rule = {
            "reverse_template": "SRC={src_ip} DST={dst_ip} PROTO={proto} DPT={port}"
        }

        result = verify_reconstruction(raw_bytes, parsed_fields, rule)
        self.assertEqual(result["verdict"], "pass")
        self.assertIsNone(result["diff"])

    def test_reconstruction_fail_field_truncation(self):
        """Test that a broken rule (truncated field or dropped character) fails and diff specifies byte offset."""
        raw_wire = "SRC=198.51.100.23 DST=10.0.0.1 PROTO=TCP DPT=443"
        raw_bytes = raw_wire.encode("utf-8")

        # Deliberately broken: missing the leading '198.' in IP or mistyped DST
        parsed_fields = {
            "src_ip": "51.100.23",  # truncated
            "dst_ip": "10.0.0.1",
            "proto": "TCP",
            "port": "443"
        }

        rule = {
            "reverse_template": "SRC={src_ip} DST={dst_ip} PROTO={proto} DPT={port}"
        }

        result = verify_reconstruction(raw_bytes, parsed_fields, rule)
        self.assertEqual(result["verdict"], "fail")
        self.assertIsNotNone(result["diff"])
        # Ensure the diff specifies the byte offset and mismatch specifics
        self.assertIn("byte offset", result["diff"].lower())
        self.assertIn("expected", result["diff"].lower())
        self.assertIn("got", result["diff"].lower())

    def test_reconstruction_fail_length_mismatch(self):
        """Test that dropping a trailing token produces a length mismatch diff."""
        raw_wire = "AUTH user=admin status=OK"
        raw_bytes = raw_wire.encode("utf-8")

        parsed_fields = {
            "user": "admin"
        }

        rule = {
            "reverse_template": "AUTH user={user}"  # dropped status=OK
        }

        result = verify_reconstruction(raw_bytes, parsed_fields, rule)
        self.assertEqual(result["verdict"], "fail")
        self.assertIsNotNone(result["diff"])
        self.assertIn("length mismatch", result["diff"].lower())

    def test_reconstruction_unstructured_raw_fallback(self):
        """Test that unstructured raw logs fallback to verbatim byte equivalence cleanly."""
        raw_msg = "Oct 27 10:14:02 server kernel: [PANIC] CPU 0: unable to handle kernel NULL pointer dereference"
        raw_bytes = raw_msg.encode("utf-8")

        parsed_fields = {
            "unstructured_raw": raw_msg,
            "severity": "Critical"
        }

        # Rule without explicit reverse_template
        rule = {}
        result = verify_reconstruction(raw_bytes, parsed_fields, rule)
        self.assertEqual(result["verdict"], "pass")
        self.assertIsNone(result["diff"])


if __name__ == "__main__":
    unittest.main()
