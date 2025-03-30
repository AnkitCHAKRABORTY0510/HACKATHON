import pandas as pd

# Load dataset
df = pd.read_csv("captured_traffic.csv")

# Define window size
WINDOW_SIZE = 1000

# Function to classify attacks using a rolling window
def classify_with_window(index, df_window, src_ip):
    flags = df_window["Flags"].tolist()
    attack_types = df_window["Attack_Type"].tolist()
    protocols = df_window["Protocol"].tolist()
    src_ips = df_window["Src_IP"].tolist()  # Track Source IPs

    current_entry = df.iloc[index]
    flag = current_entry["Flags"]
    attack_type = current_entry["Attack_Type"]

    # Observation 1: Normal Traffic
    if flag == "NA":
        return "Normal"

    # Observation 2: SYN Flood Attack
    if attack_type == "bruteforce" and flag == "S":
        if "PA" in flags and "A" in flags:
            return "SYN Flood Attack"

    # Observation 3: DDoS Attack (Brute Force with multiple SYN packets)
    if attack_type == "bruteforce" and flags.count("S") > 100:
        return "DDoS (SYN Flood)"

    # Observation 4: UDP Flooding
    if "bruteforce" in attack_types and "UDP" in protocols and "Normal" in attack_types:
        return "UDP Flooding"

    # Observation 5: ICMP Flooding
    if "ICMP" in attack_type:
        return "ICMP Flooding"

    # Observation 6: Port Scan Detection
    port_scan_keywords = ["Nmap SYN Scan", "Slow Port Scan", "Unusual Scan", "Aggressive Port Scan", "SYNC flood"]
    has_port_scan = any(keyword in attack_types for keyword in port_scan_keywords)

    # Observation 7: SQL Injection should override Port Scan if same Src_IP is involved
    sql_injection_present = "SQL Injection" in attack_types
    if sql_injection_present and src_ip in src_ips:
        return "SQL Injection"  # Override Port Scan

    # If no SQL Injection detected, classify as Port Scan
    if has_port_scan:
        return "Port Scan"

    return attack_type  # Default case

# Apply rolling window classification
df["Processed_Attack_Type"] = ""

for i in range(len(df)):
    start_idx = max(0, i - WINDOW_SIZE)
    df_window = df.iloc[start_idx:i]  # Extract rolling window
    src_ip = df.iloc[i]["Src_IP"]  # Track source IP
    df.at[i, "Processed_Attack_Type"] = classify_with_window(i, df_window, src_ip)

# Function to categorize attacks into broader categories
def categorize_attack(attack_type):
    if attack_type == "Normal":
        return "Benign"
    elif "Brute Force" in attack_type:
        return "Brute Force"
    elif "DDoS" in attack_type:
        return "DDoS"
    elif "ICMP" in attack_type:
        return "ICMP Attack"
    elif "Port Scan" in attack_type:
        return "Port Scanning"
    elif "SQL Injection" in attack_type:
        return "SQL Injection"
    else:
        return "Other Attack"

# Apply attack categorization function
df["Attack_Category"] = df["Processed_Attack_Type"].apply(categorize_attack)

# Save processed dataset
df.to_csv("processed_data.csv", index=False)

print("Preprocessing complete. Saved as processed_data.csv")
