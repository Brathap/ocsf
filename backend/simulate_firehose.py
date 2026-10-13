import socket
import time
import random
from datetime import datetime

TARGET_HOST = "127.0.0.1"
TARGET_PORTS = [514, 5140]

SAMPLE_LOGS = [
    # Cisco ASA Firewall Log (External Threat)
    '%ASA-4-106023: Deny tcp src outside:198.51.100.23/51412 dst inside:10.0.0.15/443 by access-group "OUTSIDE-IN"',
    # Cisco ASA Firewall Log (Internal Authorized)
    '%ASA-6-302013: Built outbound TCP connection 49102 for outside:192.168.1.100/5412 (10.0.0.50/5412) to inside:10.0.0.1/80',
    # Linux Server Auth Failure (Lazarus Group Threat)
    'Oct 24 10:14:22 gateway sshd[24190]: Failed password for invalid user root from 203.0.113.84 port 43210 ssh2 session_ref=982345129081',
    # Linux Server Auth Success with unredacted Aadhaar
    'Oct 24 10:15:02 auth-node-02 sshd[24201]: Accepted publickey for secops from 10.0.0.55 port 51234 ssh2 citizen_aadhaar=452178902341',
    # Imperva / ArcSight CEF with raw unredacted Indian Aadhaar PII
    'CEF:0|Imperva|WAF|14.0|SQLI|SQL Injection Attempt|9|src=198.51.100.23 dst=10.1.1.20 dpt=80 user=priya.verma national_id=671234908123',
    # Palo Alto VPN Success with Aadhaar token
    'CEF:0|PaloAltoNetworks|PAN-OS|10.1|AUTH|GlobalProtect login|3|src=10.0.2.15 dst=172.16.0.4 dpt=443 act=allow user=arun.kumar gov_id=239012458712',
    # Windows Security Event Audit Failure (Volt Typhoon threat)
    '<13>1 2026-09-24T12:20:00Z dc01.corp Microsoft-Windows-Security-Auditing 4625 - - src=103.21.244.12 Failure Reason: Unknown user name or bad password.',
    # Cloudflare / Reverse Proxy WAF block (Sandworm threat)
    'CEF:0|Cloudflare|Edge-WAF|2.1|RULE_942100|Malicious User-Agent Blocked|7|src=192.0.2.145 dst=172.16.0.20 dpt=443 act=block'
]

print("=" * 65)
print("  ULPF Firehose Simulator (SIH 26156)")
print(f"  Target: UDP {TARGET_HOST} Ports {TARGET_PORTS}")
print("  Rate: ~5 logs/second")
print("=" * 65)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    while True:
        raw_template = random.choice(SAMPLE_LOGS)
        timestamp = datetime.utcnow().strftime("%b %d %H:%M:%S")
        log_payload = f"{timestamp} {raw_template}".encode("utf-8")
        
        for port in TARGET_PORTS:
            try:
                sock.sendto(log_payload, (TARGET_HOST, port))
            except Exception:
                pass
        print(f"[EMITTED] {raw_template[:65]}...")
        time.sleep(0.2)
except KeyboardInterrupt:
    print("\nSimulator stopped by user.")
finally:
    sock.close()