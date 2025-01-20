import subprocess
import ipaddress
import os
import platform

def ping_ip(ip):
    # Determine the system's ping command
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # Ping the IP address with 1 packet
    command = ['ping', param, '1', str(ip)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Check if the host is reachable
    if result.returncode == 0:
        return True
    else:
        return False

def detect_live_hosts(subnet):
    live_hosts = []
    network = ipaddress.IPv4Network(subnet, strict=False)
    
    # Iterate over all hosts in the subnet and ping each IP
    for ip in network.hosts():
        print(f"Pinging {ip}...")
        if ping_ip(ip):
            print(f"{ip} is alive.")
            live_hosts.append(str(ip))
        else:
            print(f"{ip} is not reachable.")
    
    return live_hosts

if __name__ == '__main__':
    subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ")
    
    print("\nDetecting live hosts...\n")
    live_hosts = detect_live_hosts(subnet)
    
    if live_hosts:
        print("\nLive hosts detected:")
        for host in live_hosts:
            print(host)
    else:
        print("\nNo live hosts detected.")