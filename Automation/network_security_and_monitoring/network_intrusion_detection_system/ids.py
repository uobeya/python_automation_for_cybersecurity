import os
import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, Raw

# Load pre-trained machine learning model (Random Forest in this case)
MODEL_PATH = "/home/udeh/Desktop/python_automation_for_cybersecurity/Automation/network_security_and_monitoring/network_intrusion_detection_system/network_anomaly_model.pkl"

if not os.path.exists(MODEL_PATH):
    print(f"Model not found at {MODEL_PATH}. Train and save the model first.")
    exit()

model = joblib.load(MODEL_PATH)

# Feature extraction from packets
def extract_features(packet):
    """
    Extracts relevant features from a network packet.
    """
    features = {
        "src_ip": packet[IP].src if packet.haslayer(IP) else "0.0.0.0",
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else "0.0.0.0",
        "src_port": packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0),
        "dst_port": packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0),
        "packet_size": len(packet),
        "is_tcp": 1 if packet.haslayer(TCP) else 0,
        "is_udp": 1 if packet.haslayer(UDP) else 0,
        "is_raw": 1 if packet.haslayer(Raw) else 0,
    }
    return features

# Analyze packet using the ML model
def analyze_packet(packet):
    """
    Analyzes a network packet for anomalies using a machine learning model.
    """
    features = extract_features(packet)
    feature_df = pd.DataFrame([features])
    feature_df.drop(columns=["src_ip", "dst_ip"], inplace=True)  # Drop non-numeric columns for the model
    
    prediction = model.predict(feature_df)
    if prediction == 1:  # Assume '1' indicates an anomaly
        print(f"[ALERT] Anomalous traffic detected: {features}")
    else:
        print(f"[INFO] Normal traffic: {features}")

# Monitor and analyze network traffic
def monitor_traffic(interface="eth0", duration=60):
    """
    Captures and analyzes network traffic for anomalies.
    Args:
        interface (str): Network interface to monitor.
        duration (int): Duration to monitor in seconds.
    """
    print(f"Monitoring network traffic on {interface} for {duration} seconds...")
    sniff(iface=interface, prn=analyze_packet, timeout=duration)
    print("Monitoring complete.")

if __name__ == "__main__":
    # User inputs for network interface and monitoring duration
    network_interface = input("Enter the network interface (e.g., eth0, wlan0): ") or "eth0"
    monitoring_duration = int(input("Enter the monitoring duration (seconds): ") or 60)

    monitor_traffic(interface=network_interface, duration=monitoring_duration)
