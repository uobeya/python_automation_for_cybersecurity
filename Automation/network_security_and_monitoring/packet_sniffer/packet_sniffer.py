from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# Initialize data structures for tracking suspicious activities
connection_attempts = defaultdict(int)
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 1433, 3306]  # SSH, Telnet, RDP, SMB, MSSQL, MySQL
THRESHOLD = 9  # Max allowed connection attempts per src IP in a minute
DURATION = 59 # default scan duration (59 seconds)

# Function to analyze each captured packet
def analyze_packet(packet):

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check for TCP or UDP packets
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            connection_attempts[(src_ip, dst_port)] += 1

            # Log packet details
            print(f"[TCP] {src_ip} --> {dst_ip}::{dst_port}")

            # Detect repeated connection attempts (port scan behavior)
            if connection_attempts[(src_ip, dst_port)] > THRESHOLD:
                print(f"[ALERT] Potential port scan detected from {src_ip} on port {dst_port}!")

            # Check if the destination port is sensitive
            if dst_port in SUSPICIOUS_PORTS:
                print(f"[INFO] Traffic to sensitive port {dst_port} detected from {src_ip}.")

        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            print(f"[UDP] {src_ip} --> {dst_ip}:{dst_port}")
            
            # Check if the destination port is sensitive
            if dst_port in SUSPICIOUS_PORTS:
                print(f"[INFO] UDP traffic to sensitive port {dst_port} detected from {src_ip}.")

# Fn to monitor traffic on a specific interface
def monitor_traffic(interface="eth0", duration=DURATION):
    """
    Monitors network traffic for suspicious patterns.
    Args:
        interface (str): Network interface to monitor (e.g., eth0, wlan0).
        duration (int): Duration to capture packets, in seconds.
    """
    print(f"Monitoring network traffic on {interface} for {duration} seconds...")
    start_time = time.time()

    # Capture packets and analyze them
    sniff(iface=interface, prn=analyze_packet, timeout=duration)
    
    print("Traffic monitoring completed.")

# Script execution
if __name__ == "__main__":
    # Get user input for the network interface and monitoring duration
    network_interface = input("Enter the network interface (e.g., eth0, wlan0): ") or "eth0"
    monitoring_duration = int(input("Enter the monitoring duration in seconds: ") or DURATION)

    monitor_traffic(interface=network_interface, duration=monitoring_duration)