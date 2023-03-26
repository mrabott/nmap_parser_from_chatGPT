import nmap
import sqlite3
import sys

# Database setup
def create_database():
    conn = sqlite3.connect("nmap_results.db")
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY,
            ip_address TEXT,
            host_name TEXT,
            os_name TEXT
        );
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY,
            host_id INTEGER,
            port_number INTEGER,
            state TEXT,
            service_name TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (id)
        );
        """
    )
    conn.commit()
    return conn


def store_results(conn, ip, host_name, os_name, ports):
    c = conn.cursor()
    c.execute("INSERT INTO hosts (ip_address, host_name, os_name) VALUES (?, ?, ?)", (ip, host_name, os_name))
    host_id = c.lastrowid

    for port in ports:
        c.execute(
            "INSERT INTO ports (host_id, port_number, state, service_name) VALUES (?, ?, ?, ?)",
            (host_id, port["port"], port["state"], port["service"]),
        )
    conn.commit()


# Nmap scan and parsing
def nmap_scan(ip_addresses, ports):
    nm = nmap.PortScanner()
    scan_range = ",".join(ip_addresses)
    port_range = ",".join(ports)

    nm.scan(scan_range, port_range, arguments="-O")
    return nm


def parse_nmap_results(nmap_results):
    parsed_results = []

    for host in nmap_results.all_hosts():
        host_info = {
            "ip": host,
            "host_name": nmap_results[host]["hostnames"][0]["name"] if nmap_results[host]["hostnames"] else "",
            "os_name": nmap_results[host].get("osclass", {}).get("osfamily", ""),
            "ports": [],
        }

        for port_info in nmap_results[host]["tcp"].values():
            host_info["ports"].append({
                "port": port_info["portid"],
                "state": port_info["state"],
                "service": port_info["name"],
            })

        parsed_results.append(host_info)

    return parsed_results


# Main function
def main():
    if len(sys.argv) < 3:
        print("Usage: nmap_parser.py <comma-separated ip addresses> <comma-separated ports>")
        sys.exit(1)

    ip_addresses = sys.argv[1].split(",")
    ports = sys.argv[2].split(",")

    nmap_results = nmap_scan(ip_addresses, ports)
    parsed_results = parse_nmap_results(nmap_results)

    conn = create_database()

    for host_info in parsed_results:
        store_results(conn, host_info["ip"], host_info["host_name"], host_info["os_name"], host_info["ports"])

    conn.close()
    print("Results stored in nmap_results.db")


if __name__ == "__main__":
    main()