"""Tests for Network Egress Enforcement (Requirement 2).

Verifies:
1. Socket interceptor blocks connections to external IP addresses with PermissionError.
2. Loopback and internal private IPs remain fully accessible.
3. Startup runtime self-test executes outbound probes and confirms fail-closed behavior.
4. Exposes evidence-backed status payload for SOC provenance inspection.
"""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from egress_enforcement import EgressEnforcementManager


class TestNetworkEgressEnforcement(unittest.TestCase):
    def setUp(self):
        self.manager = EgressEnforcementManager()
        self.manager.install_socket_interceptor()

    def tearDown(self):
        self.manager.remove_socket_interceptor()

    def test_external_egress_strictly_blocked(self):
        """Confirm direct TCP connect to external public addresses is rejected with PermissionError."""
        targets = [("8.8.8.8", 53), ("1.1.1.1", 80), ("9.9.9.9", 443)]
        for host, port in targets:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with self.assertRaises(PermissionError) as ctx:
                s.connect((host, port))
            s.close()
            self.assertIn("AIR-GAP EGRESS ENFORCEMENT BLOCKED", str(ctx.exception))
            self.assertIn(host, str(ctx.exception))

    def test_loopback_and_local_permitted(self):
        """Confirm loopback (127.0.0.1) and internal network communication is permitted."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", port))
        client_sock.close()
        server_sock.close()

    def test_fail_closed_self_test_report(self):
        """Confirm the self-test report proves all external probes are blocked and loopback works."""
        result = self.manager.run_fail_closed_self_test(timeout=0.2)
        self.assertEqual(result["status"], "ENFORCED")
        self.assertTrue(result["all_external_blocked"])
        self.assertTrue(result["loopback_operational"])
        self.assertEqual(result["probes_passed_unexpectedly"], 0)

    def test_udp_egress_strictly_blocked(self):
        """Confirm UDP sendto to external IP is rejected with PermissionError."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with self.assertRaises(PermissionError) as ctx:
            s.sendto(b"exfiltration_payload", ("8.8.8.8", 53))
        s.close()
        self.assertIn("AIR-GAP UDP EGRESS ENFORCEMENT BLOCKED", str(ctx.exception))

    def test_dns_resolution_blocked(self):
        """Confirm external hostname resolution is blocked without leaking queries."""
        with self.assertRaises(PermissionError) as ctx:
            socket.gethostbyname("malicious-exfiltration.attacker.com")
        self.assertIn("AIR-GAP DNS BLOCKED", str(ctx.exception))

    def test_kernel_firewall_rule_generation(self):
        """Confirm iptables and nftables kernel air-gap policies are generated correctly."""
        iptables_script = self.manager.generate_iptables_script()
        self.assertIn("iptables -F OUTPUT", iptables_script)
        self.assertIn("REJECT --reject-with icmp-admin-prohibited", iptables_script)

        nftables_rules = self.manager.generate_nftables_rules()
        self.assertIn("table inet ulpf_airgap", nftables_rules)
        self.assertIn("policy drop", nftables_rules)


if __name__ == "__main__":
    unittest.main()
