from scapy.all import sniff, TCP, IP
from collections import Counter
import time

# Initialize counters and thresholds
connection_attempts = Counter()
THRESHOLD = 9  # Max allowed connection attempts per IP in a minute

def analyze_packet(packet):
    """
    Analyzes a captured packet for suspicious activity.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Log the packet
            print(f"Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            # Detect port scan (frequent connection attempts)
            connection_attempts[(src_ip, dst_ip)] += 1
            if connection_attempts[(src_ip, dst_ip)] > THRESHOLD:
                print(f"[ALERT] Potential port scan detected from {src_ip} to {dst_ip}!")

            # Checking specific suspicious ports, e.g. SSH brute force
            if dst_port == 22:  # SSH
                print(f"[INFO] SSH traffic detected from {src_ip} to {dst_ip}")

def monitor_network(interface="eth0", duration=60):
    """
    Monitors network traffic on a specified interface for a duration.
    Args:
        interface (str): The network interface to monitor.
        duration : Duration to monitor in seconds.
    """
    print(f"Monitoring traffic on {interface} for {duration} seconds...")
    start_time = time.time()

    def stop_condition(packet):
        # Stop after the duration given
        return time.time() - start_time > duration

    sniff(iface=interface, prn=analyze_packet, stop_filter=stop_condition)
    print("Monitoring complete.")

if __name__ == "__main__":
    # Specify the network interface and monitoring duration
    network_interface = input("Enter the network interface (e.g., eth0): ") or "eth0"
    monitoring_duration = int(input("Enter the monitoring duration (seconds): ") or 60)

    monitor_network(interface=network_interface, duration=monitoring_duration)