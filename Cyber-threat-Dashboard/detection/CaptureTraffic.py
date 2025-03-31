from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
import pandas as pd
import time
import re
import os
from collections import defaultdict

# Track attack patterns
traffic_count = defaultdict(lambda: {"count": 0, "first_seen": time.time()})
login_attempts = defaultdict(list)
port_scan_attempts = defaultdict(lambda: {"ports": set(), "syn_count": 0, "ack_count": 0, "first_seen": None})

# File to store captured traffic
csv_file = "../backend/captured_traffic.csv"

# Thresholds to reduce false positives
SYN_FLOOD_THRESHOLD = 500
UDP_FLOOD_THRESHOLD = 1000
ICMP_FLOOD_THRESHOLD = 500
BRUTE_FORCE_THRESHOLD = 200
PORT_SCAN_THRESHOLD = 100
UNCOMMON_PORT_SCAN_THRESHOLD = 90
SYN_SCAN_THRESHOLD = 70
SLOW_SCAN_THRESHOLD = 80
PORT_SCAN_WINDOW = 5  # Seconds for fast scans
SLOW_SCAN_TIME_LIMIT = 60  # Seconds for slow scans
COMMON_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995, 3306, 3389}

# Detect attacks
def detect_attack(packet):
    attack_type = "Normal"
    payload = ""

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        packet_length = len(packet)
        ttl = packet[IP].ttl
        flags = packet[TCP].flags if packet.haslayer(TCP) else "N/A"

        traffic_count[src_ip]["count"] += 1
        src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
        dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"

        # SYN Flood Detection
        if packet.haslayer(TCP) and packet[TCP].flags == 2:
            if traffic_count[src_ip]["count"] > SYN_FLOOD_THRESHOLD:
                attack_type = "SYN Flood"

        # UDP Flood Detection
        if packet.haslayer(UDP):
            if traffic_count[src_ip]["count"] > UDP_FLOOD_THRESHOLD:
                attack_type = "UDP Flood"

        # ICMP Flood Detection
        if packet.haslayer(ICMP):
            if traffic_count[src_ip]["count"] > ICMP_FLOOD_THRESHOLD:
                attack_type = "ICMP Flood"

        # Brute Force Attack Detection
        if packet.haslayer(TCP) and packet[TCP].dport in [22, 21, 80, 443, 3389]:
            login_attempts[src_ip].append(time.time())
            if len(login_attempts[src_ip]) > BRUTE_FORCE_THRESHOLD:
                attack_type = "Brute Force Attack"

        # Port Scan Detection
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port_scan_attempts[src_ip]["ports"].add(dst_port)
            elapsed_time = time.time() - port_scan_attempts[src_ip]["first_seen"] if port_scan_attempts[src_ip]["first_seen"] else 0

            if packet.haslayer(TCP) and packet[TCP].flags == 2:
                port_scan_attempts[src_ip]["syn_count"] += 1

            if port_scan_attempts[src_ip]["syn_count"] > SYN_SCAN_THRESHOLD:
                attack_type = "Nmap SYN Scan"
            elif len(port_scan_attempts[src_ip]["ports"]) > PORT_SCAN_THRESHOLD and elapsed_time < PORT_SCAN_WINDOW:
                attack_type = "Aggressive Port Scan"
            elif len(port_scan_attempts[src_ip]["ports"]) > SLOW_SCAN_THRESHOLD:
                attack_type = "Slow Port Scan"
            elif len(port_scan_attempts[src_ip]["ports"] - COMMON_PORTS) > UNCOMMON_PORT_SCAN_THRESHOLD:
                attack_type = "Unusual Port Scan"

        # SQL Injection Detection
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            sql_patterns = [
                r"(SELECT\s+.*\s+FROM\s+.*)", r"(DROP\s+TABLE\s+.*)", r"(UNION\s+SELECT\s+.*)",
                r"(INSERT\s+INTO\s+.*)", r"(--|#|/\\*)", r"(\bor\b\s+1=1\b)", r"(;.*DROP\s+TABLE)",
                r"(%27|%22|%3D|%3B)"
            ]
            if sum(bool(re.search(pattern, payload, re.IGNORECASE)) for pattern in sql_patterns) >= 3:
                attack_type = "SQL Injection"

        # XSS Detection
        xss_patterns = [r"<script>.*</script>", r"onmouseover=.*", r"alert\(.*\)"]
        if payload and any(re.search(pattern, payload, re.IGNORECASE) for pattern in xss_patterns):
            attack_type = "XSS Attack"

        # ARP Spoofing Detection
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            attack_type = "ARP Spoofing"

        # DNS Tunneling Detection
        if packet.haslayer(UDP) and packet[UDP].dport == 53 and packet.haslayer(Raw):
            if len(packet[Raw].load.decode(errors="ignore")) > 200:
                attack_type = "DNS Tunneling"

        # Log detected attack
        print(f"[{attack_type}] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({packet_length} bytes)")

        # Save packet data
        save_data({
            "Timestamp": time.time(), "Src_IP": src_ip, "Dst_IP": dst_ip,
            "Src_Port": src_port, "Dst_Port": dst_port, "Protocol": proto,
            "Packet_Size": packet_length, "TTL": ttl, "Flags": flags, "Attack_Type": attack_type
        })

# Append data to CSV file
def save_data(data):
    df = pd.DataFrame([data])
    file_exists = os.path.isfile(csv_file)
    df.to_csv(csv_file, mode="a", header=not file_exists, index=False)
    print("✅ Data saved to captured_traffic.csv")

# Capture live packets
def packet_sniffer():
    print("🔥 Capturing live network traffic (CTRL+C to stop)...")
    sniff(prn=detect_attack, store=False, filter="ip or arp", iface="en0")

# Run the sniffer
try:
    packet_sniffer()
except KeyboardInterrupt:
    print("\n⚠️ Stopping packet capture...")
