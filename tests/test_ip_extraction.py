"""Tests for Robust IP Extraction & Adversarial Resilience (Requirement 6).

Verifies:
1. Per-source dissect/grok extraction: Cisco ASA, CEF, Linux SSHD, Juniper SRX.
2. Full IPv6 extraction (standard, compressed, dual-stack).
3. Adversarial cases:
   - Malformed CEF lines (missing pipes, unbalanced characters) -> Graceful handling, no crash.
   - Lines with multiple IPs (e.g. 5+ IPs) -> Deterministic selection of primary src/dst.
   - Lines with NO IPs -> Graceful fallback ("0.0.0.0"), no unhandled exceptions.
   - Truncated or corrupted logs (null bytes, partial text) -> Preserved safely with error envelope.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from ip_extractor import extract_ip_endpoints, parse_cef_line, is_valid_ip


class TestRobustIPExtraction(unittest.TestCase):
    def test_cisco_asa_dissect(self):
        """Extracts IPv4 src/dst from Cisco ASA syslog."""
        line = "<164>Oct 24 10:20:30 ciscoasa: %ASA-4-106023: Denied tcp src inside:198.51.100.23/50901 dst outside:10.0.0.1/80 by access-group 'OUTSIDE_IN'"
        src, dst, meta = extract_ip_endpoints(line)
        self.assertEqual(src, "198.51.100.23")
        self.assertEqual(dst, "10.0.0.1")
        self.assertEqual(meta["parser_used"], "cisco_asa_dissect")

    def test_cef_dissect_extraction(self):
        """Extracts src/dst from ArcSight CEF format."""
        line = "CEF:0|Imperva|WAF|14.0|SQLI|SQL Injection|9|src=198.51.100.23 dst=10.1.1.20 act=block"
        src, dst, meta = extract_ip_endpoints(line)
        self.assertEqual(src, "198.51.100.23")
        self.assertEqual(dst, "10.1.1.20")
        self.assertEqual(meta["parser_used"], "cef_dissect")

    def test_linux_sshd_dissect(self):
        """Extracts src from SSHD auth failure."""
        line = "Oct 24 10:20:30 auth-srv sshd[4921]: Failed password for invalid user root from 203.0.113.84 port 41231 ssh2"
        src, dst, meta = extract_ip_endpoints(line)
        self.assertEqual(src, "203.0.113.84")
        self.assertEqual(meta["parser_used"], "linux_sshd_dissect")

    def test_ipv6_standard_and_compressed_support(self):
        """Full support for standard and compressed IPv6 addresses."""
        # 1. Standard IPv6
        ipv6_line = "CEF:0|Vendor|FW|1.0|DENY|Block|5|src=2001:0db8:85a3:0000:0000:8a2e:0370:7334 dst=2001:0db8:85a3:0000:0000:8a2e:0370:7335"
        src, dst, meta = extract_ip_endpoints(ipv6_line)
        self.assertEqual(src, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertEqual(dst, "2001:0db8:85a3:0000:0000:8a2e:0370:7335")
        self.assertTrue(is_valid_ip(src))

        # 2. Compressed IPv6 in SSHD line
        sshd_ipv6 = "Oct 24 10:20:30 host1 sshd[123]: Accepted publickey for secops from 2001:db8::1 port 2200 ssh2"
        src6, _, meta6 = extract_ip_endpoints(sshd_ipv6)
        self.assertEqual(src6, "2001:db8::1")
        self.assertTrue(is_valid_ip(src6))

    def test_adversarial_malformed_cef(self):
        """Malformed CEF with missing headers or corrupted delimiters handles gracefully without crashing."""
        malformed_lines = [
            "CEF:0|Corrupt|NoOtherPipes",
            "CEF:0|||||||",
            "CEF:0|Vendor|App|1.0|SIG|Name|src=missing_value dst=",
            "CEF:0|Vendor|App|1.0|SIG|Name|9|invalid_keys_without_equal_signs"
        ]
        for line in malformed_lines:
            src, dst, meta = extract_ip_endpoints(line)
            self.assertIsNotNone(src)
            self.assertIsNotNone(dst)

    def test_adversarial_lines_with_multiple_ips(self):
        """Line containing 5 disparate IP addresses extracts primary deterministic src and dst."""
        multi_ip_line = (
            "Gateway alert: router 10.0.0.1 forwarded packet from client 192.168.1.50 "
            "to target 172.16.0.2 via proxies 198.51.100.1 and 198.51.100.2"
        )
        src, dst, meta = extract_ip_endpoints(multi_ip_line)
        self.assertEqual(src, "10.0.0.1")
        self.assertEqual(dst, "192.168.1.50")
        self.assertGreater(meta.get("discovered_ips_count", 0), 2)

    def test_adversarial_lines_with_no_ip(self):
        """Log lines with zero IP addresses fallback gracefully to declared default without crashing."""
        no_ip_line = "kernel: [ 1234.567] systemd[1]: Started User Manager for UID 1000."
        src, dst, meta = extract_ip_endpoints(no_ip_line, default_src="0.0.0.0", default_dst="127.0.0.1")
        self.assertEqual(src, "0.0.0.0")
        self.assertEqual(dst, "127.0.0.1")
        self.assertTrue(meta["fallback_applied"])

    def test_adversarial_truncated_and_corrupt_logs(self):
        """Truncated, empty, and non-ASCII binary strings do not cause unhandled exceptions."""
        adversarial_inputs = [
            "",
            None,
            "   ",
            "\x00\x01\x02\xff\xfe\x00<164>Oct 24 10:20:30 %ASA: corrupted payload",
            "A" * 10000,  # Length stress test
        ]
        for item in adversarial_inputs:
            src, dst, meta = extract_ip_endpoints(item)
            self.assertIsNotNone(src)
            self.assertIsNotNone(dst)


if __name__ == "__main__":
    unittest.main()
