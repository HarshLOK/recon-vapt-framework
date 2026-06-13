import nmap


def run_port_scan(host: str, ports: str = "22,80,443,3306,5432,8080,8443") -> dict:
    """
    Scan common ports on a host.
    Returns open ports with service info.
    """
    print(f"  [PORT] Scanning {host} — ports: {ports}")
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=host, ports=ports, arguments="-sV --open")
    except Exception as e:
        print(f"  [PORT] Scan error: {e}")
        return {}

    results = {}
    for host_ip in scanner.all_hosts():
        results[host_ip] = {}
        for proto in scanner[host_ip].all_protocols():
            results[host_ip][proto] = {}
            for port in scanner[host_ip][proto]:
                info = scanner[host_ip][proto][port]
                if info["state"] == "open":
                    results[host_ip][proto][port] = {
                        "state":   info["state"],
                        "service": info["name"],
                        "version": info.get("version", ""),
                        "product": info.get("product", ""),
                    }

    return results