import socket
import nmap

def scan_open_ports(target_ip, port_range):
  
    open_ports = []

    print(f"Starting port scan on {target_ip} for ports {port_range[0]}-{port_range[1]}...\n")

    # Scan for open ports using socket
    for port in range(port_range[0], port_range[1] + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"[OPEN] Port {port}")
            sock.close()
        except Exception as e:
            print(f"[ERROR] Could not connect to port {port}: {e}")

    print("\nPort scanning with socket completed.\n")

    # Use Nmap to identify services and vulnerabilities
    if open_ports:
        print("Starting Nmap scan for additional information...\n")
        nm = nmap.PortScanner()

        try:
            for port in open_ports:
                scan_result = nm.scan(target_ip, str(port), arguments='-sV --script vuln')
                port_info = scan_result['scan'][target_ip]['tcp'][port]

                print(f"Port {port}:")
                print(f"  Service: {port_info.get('name', 'Unknown')}")
                print(f"  Version: {port_info.get('version', 'Unknown')}")
                print(f"  Vulnerabilities: {port_info.get('script', 'None')}")

        except KeyError:
            print("Error processing Nmap results. Ensure the target is reachable and Nmap is installed.")
        except Exception as e:
            print(f"An error occurred while running Nmap: {e}")
    else:
        print("No open ports found. Skipping Nmap scan.")

if __name__ == "__main__":
    # User input for target and port range
    target = input("Enter the target IP address: ")
    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))

    # Check to ensure valid inputs
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range. Please enter a valid range (1-65535).")
    else:
        scan_open_ports(target, (start_port, end_port))