import scapy.all as scapy
import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler

# Load trained model & encoders
rf_model = joblib.load("cyber_threat_model.pkl")
scaler = joblib.load("scaler.pkl")
attack_classes = joblib.load("attack_classes.pkl")  # {0: "Normal", 1: "ICMP Flood", etc.}
label_encoders = joblib.load("label_encoders.pkl")  # Encoders for Protocol, Flags, Src_Port, Dst_Port

# Function to extract features from live packet
def extract_features(packet):
    try:
        src_port = packet.sport if hasattr(packet, "sport") else 0
        dst_port = packet.dport if hasattr(packet, "dport") else 0
        protocol = packet.proto if hasattr(packet, "proto") else 0
        packet_size = len(packet)
        ttl = packet.ttl if hasattr(packet, "ttl") else 64
        flags = packet.sprintf("%TCP.flags%") if "TCP" in packet else "N/A"

        # Print Port Information (🔍 Debugging Step)
        print(f"🌐 Packet Captured → Src Port: {src_port}, Dst Port: {dst_port}")

        # Convert categorical values using stored encoders
        def encode_value(encoder, value, default=0):
            return encoder.transform([str(value)])[0] if str(value) in encoder.classes_ else default

        src_port_encoded = encode_value(label_encoders["Src_Port"], src_port)
        dst_port_encoded = encode_value(label_encoders["Dst_Port"], dst_port)
        protocol_encoded = encode_value(label_encoders["Protocol"], protocol)
        flags_encoded = encode_value(label_encoders["Flags"], flags)

        # Create feature array
        features = np.array([[packet_size, ttl, src_port_encoded, dst_port_encoded, protocol_encoded, flags_encoded]])

        # Normalize data
        features_scaled = scaler.transform(features)
        
        return features_scaled

    except Exception as e:
        print(f"⚠️ Error extracting features: {e}")
        return None

# Function to process live packets
def process_packet(packet):
    features = extract_features(packet)
    if features is None:
        return

    # Predict attack type
    prediction = rf_model.predict(features)[0]
    attack_name = attack_classes.get(prediction, "Unknown Attack")

    # Alert if attack detected
    if attack_name != "Normal":
        print(f"\n🚨 ALERT: {attack_name} Detected! 🚨\n")
    else:
        print("✅ Normal Traffic")

# Start live network traffic capture
print("\n🔍 Monitoring Live Network Traffic for Cyber Threats...\n")
scapy.sniff(prn=process_packet, store=False)
