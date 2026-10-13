import socket
import time
import random
import datetime

UDP_IP = "127.0.0.1"
UDP_PORT = 5140

# Setting up the network socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Mix of normal internal IPs and the Malicious IPs from your CSV
ips = [
    "192.168.1.100", "10.0.0.55", "172.16.0.12", "192.168.1.105", # Normal
    "198.51.100.23", "203.0.113.84", "192.0.2.145", "103.21.244.12", "198.51.100.99", "203.0.113.111" # Malicious
]

templates = [
    "INFO: Connection permitted over port 443 from {ip}",
    "INFO: HTTP GET /dashboard HTTP/1.1 200 OK from {ip}",
    "WARN: Invalid login attempt for user 'admin' from {ip}",
    "CRITICAL: Multiple failed SSH login attempts detected from {ip} targeted at root gateway.",
    "INFO: User profile updated. Payload contains identity token 987654321012 in plain text from {ip}",
    "CRITICAL: Data exfiltration attempt blocked from known malicious IP {ip} over port 443."
]

print(f"Starting continuous log firehose to {UDP_IP}:{UDP_PORT}...")
print("Press Ctrl+C to stop.")

try:
    while True:
        # Generate a realistic Syslog timestamp
        now = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        ip = random.choice(ips)
        msg = random.choice(templates).format(ip=ip)
        
        # Format as raw Syslog
        syslog_packet = f"<13>{now} gateway-node: {msg}"
        
        # Blast the packet to Vector
        sock.sendto(syslog_packet.encode(), (UDP_IP, UDP_PORT))
        
        # Random delay to simulate dynamic EPS (Events Per Second)
        time.sleep(random.uniform(0.05, 0.8))

except KeyboardInterrupt:
    print("\nFirehose stopped.")
