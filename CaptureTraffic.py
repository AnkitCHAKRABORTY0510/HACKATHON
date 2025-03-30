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
csv_file = "captured_traffic.csv"

# List of common ports to reduce false positives
COMMON_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995, 3306, 3389}
PORT_SCAN_WINDOW = 5  # Seconds for fast scans
SLOW_SCAN_THRESHOLD = 60  # Seconds for slow scans
SCAN_THRESHOLD = 50  # Number of scanned ports before marking an attack

# Define attack detection logic
def detect_attack(packet):
    attack_type = "Normal"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto  # Protocol type (TCP/UDP/ICMP)
        packet_length = len(packet)

        # Track source traffic
        traffic_count[src_ip]["count"] += 1

        # Extract attributes
        src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
        dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
        ttl = packet[IP].ttl if packet.haslayer(IP) else "N/A"
        flags = packet[TCP].flags if packet.haslayer(TCP) else "N/A"

        time_elapsed = time.time() - traffic_count[src_ip]["first_seen"]

        # 🛑 **SYN Flood Detection (DDoS)**
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag
            if traffic_count[src_ip]["count"] > 200:
                attack_type = "SYN Flood"

        # 🛑 **UDP Flood Detection**
        if packet.haslayer(UDP):
            if traffic_count[src_ip]["count"] > 500:
                attack_type = "UDP Flood"

        # 🛑 **ICMP (Ping) Flood**
        if packet.haslayer(ICMP):
            if traffic_count[src_ip]["count"] > 200:
                attack_type = "ICMP Flood"

        # 🛑 **Brute Force Attack Detection**
        if packet.haslayer(TCP) and packet[TCP].dport in [22, 21, 80, 443, 3389]:
            login_attempts[src_ip].append(time.time())
            if len(login_attempts[src_ip]) > 15:
                attack_type = "Brute Force Attack"

        # 🛑 **Port Scan Detection (Improved for Nmap)**
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if port_scan_attempts[src_ip]["first_seen"] is None:
                port_scan_attempts[src_ip]["first_seen"] = time.time()

            # Track scanned ports
            port_scan_attempts[src_ip]["ports"].add(dst_port)

            # Track SYN and ACK packets separately
            if packet.haslayer(TCP):
                if packet[TCP].flags == 2:  # SYN flag
                    port_scan_attempts[src_ip]["syn_count"] += 1
                elif packet[TCP].flags == 16:  # ACK flag
                    port_scan_attempts[src_ip]["ack_count"] += 1

            # Time since first detected scan from this IP
            elapsed_time = time.time() - port_scan_attempts[src_ip]["first_seen"]

            # **Detect Stealthy SYN Scan (Nmap -sS)**
            if port_scan_attempts[src_ip]["syn_count"] > 40 and port_scan_attempts[src_ip]["ack_count"] < 10:
                attack_type = "Nmap SYN Scan"

            # **Detect Aggressive Scan**
            if len(port_scan_attempts[src_ip]["ports"]) > SCAN_THRESHOLD and elapsed_time < PORT_SCAN_WINDOW:
                attack_type = "Aggressive Port Scan"

            # **Detect Slow Scan**
            elif len(port_scan_attempts[src_ip]["ports"]) > SCAN_THRESHOLD and elapsed_time < SLOW_SCAN_THRESHOLD:
                attack_type = "Slow Port Scan"

            # **Detect Unusual Scanning (Avoid False Positives)**
            elif len(port_scan_attempts[src_ip]["ports"] - COMMON_PORTS) > 40:
                attack_type = "Unusual Port Scan"

            # Reset after threshold time
            if elapsed_time > SLOW_SCAN_THRESHOLD:
                port_scan_attempts[src_ip] = {"ports": set(), "syn_count": 0, "ack_count": 0, "first_seen": None}

        # 🛑 **SQL Injection Detection (Improved)**
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")

            # Comprehensive SQL injection detection patterns
            sql_patterns = [
                r"(SELECT\s+.*\s+FROM\s+.*)",  # Basic SELECT queries
                r"(DROP\s+TABLE\s+.*)",  # Dropping tables
                r"(UNION\s+SELECT\s+.*)",  # UNION-based injection
                r"(INSERT\s+INTO\s+.*)",  # INSERT statements
                r"(--|#|/\*)",  # SQL comments used for bypassing authentication
                r"(\bor\b\s+1=1\b)",  # Boolean-based SQL injection
                r"(;.*DROP\s+TABLE)",  # Stacked queries (SQLi)
                r"(%27|%22|%3D|%3B)"  # URL encoded SQL injection payloads
            ]

            if any(re.search(pattern, payload, re.IGNORECASE) for pattern in sql_patterns):
                attack_type = "SQL Injection"

        # 🛑 **XSS Detection**
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            xss_patterns = [r"<script>.*</script>", r"onmouseover=.*", r"alert\(.*\)"]
            if any(re.search(pattern, payload, re.IGNORECASE) for pattern in xss_patterns):
                attack_type = "XSS Attack"

        # 🛑 **ARP Spoofing Detection**
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            attack_type = "ARP Spoofing"

        # 🛑 **DNS Tunneling Detection**
        if packet.haslayer(UDP) and packet[UDP].dport == 53:
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")
                if len(payload) > 200:
                    attack_type = "DNS Tunneling"

        # Log detected attack
        print(f"[{attack_type}] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({packet_length} bytes)")

        # Store packet data
        captured_data = {
            "Timestamp": time.time(),
            "Src_IP": src_ip,
            "Dst_IP": dst_ip,
            "Src_Port": src_port,
            "Dst_Port": dst_port,
            "Protocol": proto,
            "Packet_Size": packet_length,
            "TTL": ttl,
            "Flags": flags,
            "Attack_Type": attack_type
        }

        # Append to CSV file
        save_data(captured_data)

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
