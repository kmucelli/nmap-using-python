import nmap

def check_open_ports(target_ip, port_range="1-1024", service_names=None):
    # Initialize the Nmap PortScanner
    nm = nmap.PortScanner()

    # Perform the scan
    result = nm.scan(target_ip, port_range)

    open_ports = []

    # Loop through the scan result to find open ports
    for host, scan_result in result["scan"].items():
        for port, port_info in scan_result["tcp"].items():
            if port_info["state"] == "open":
                for service_name in service_names:
                    if service_name.lower() in port_info["name"].lower():
                        open_ports.append({
                            "service_type": service_name,
                            "port": int(port),
                            "state": port_info["state"],
                            "service": port_info["name"]
                        })

    return open_ports

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with your target IP/hostname
    service_to_check = ["ssh", "udp", "tcp"]

    open_ports = check_open_ports(target_ip, service_names=service_to_check)

    for port_info in open_ports:
        print(f"Open port on {target_ip} : {port_info['port']} (Service: {port_info['service_type']}, State: {port_info['state']})")