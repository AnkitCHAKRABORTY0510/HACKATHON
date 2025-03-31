# HACKATHON
HACKVITA 3.0
# Cyber Threat Detection System

## Overview
This project is a **real-time cyber threat detection system** that captures, analyzes, and classifies network attacks using a combination of **machine learning (Random Forest) and rule-based detection**. The system includes a **dashboard** that displays live attack data and detects anomalies.

---

## 📌 Features
- **Real-time packet capture & analysis**
- **Attack classification** using machine learning (Random Forest)
- **Rule-based detection** to enhance accuracy
- **Live dashboard** to display attack patterns
- **Anomaly detection** for suspicious network behavior

---

## 📡 Data Collection & Preprocessing
### **1️⃣ Capturing Network Traffic**
- Used **Metasploitable 2 VM** as the victim and a **Linux machine** as the host.
- Collected network packets and stored them for analysis.

### **2️⃣ Observations from Packet Data**
| Attack Type  | Characteristics  | Flag  |
|-------------|----------------|------|
| **Normal Traffic** | Standard network behavior | `PA` |
| **SYN Flood Attack** | Brute force pattern | `A` |
| **DDoS Attack** | Repetitive brute force traffic | `S` |
| **UDP Flooding** | Mixture of brute force, normal, and UDP packets | `N/A` |
| **ICMP Flooding** | Clearly identifiable by attack type | `N/A` |
| **Port Scan** | Sequence of Nmap SYN Scan, Slow Port Scan, Aggressive Port Scan, etc. | Various |
| **SQL Injection** | Combination of Port Scan + Brute Force + Normal + SQL Injection | Various |

---

## 🧠 Model Training & Detection
1. **Trained a Random Forest model** on preprocessed network data.
2. Achieved **high accuracy** in attack classification.
3. **Integrated real-time detection** with a mix of **machine learning and rule-based logic**.

---

## 📊 Dashboard & Real-Time Monitoring
- **Visualizes detected cyber threats** in real time.
- **Displays attack details** such as **IP address, attack type, and timestamp**.
- **Monitors network anomalies** to detect unusual activity.

---

## 🚀 How to Run the Project
### **1️⃣ Install Dependencies**
```bash
npm install
```

### **2️⃣ Start the Backend Server**
```bash
node server.js
```

### **3️⃣ Access the Dashboard**
Open in a browser:
```
http://localhost:3000
```
### **4️⃣ Start capturing packets
```
python3 captureTraffic.py
```
---

## 🛠️ Technologies Used
- **Python** (for attack detection & machine learning)
- **Scapy** (for packet capture & analysis)
- **Node.js & Express** (backend API)
- **JavaScript, HTML, CSS** (frontend dashboard)
- **SQLite** (for logging attack data)

---

## 📌 Future Improvements
- Enhance attack detection accuracy with **deep learning** models.
- Implement **automated threat response** (e.g., IP blocking, firewall rules).
- Improve the **dashboard UI** with better data visualization.

---

## 📜 License
This project is open-source and available under the **MIT License**.

---

## 📩 Contact
For questions or contributions, feel free to reach out!

