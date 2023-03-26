import nmap
import pyodbc
import sqlite3
from typing import List, Dict, Any, Tuple


class DatabaseManager:
    def __init__(self, db_name: str):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()

    def create_tables(self) -> None:
        c = self.conn.cursor()
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
        self.conn.commit()

    def store_results(self, ip: str, host_name: str, os_name: str, ports: List[Dict[str, Any]]) -> None:
        c = self.conn.cursor()
        c.execute("INSERT INTO hosts (ip_address, host_name, os_name) VALUES (?, ?, ?)", (ip, host_name, os_name))
        host_id = c.lastrowid

        for port in ports:
            c.execute(
                "INSERT INTO ports (host_id, port_number, state, service_name) VALUES (?, ?, ?, ?)",
                (host_id, port["port"], port["state"], port["service"]),
            )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, ip_addresses: List[str], ports: List[str]) -> nmap.PortScanner:
        scan_range = ",".join(ip_addresses)
        port_range = ",".join(ports)

        self.nm.scan(scan_range, port_range, arguments="-O")
        return self.nm

    def parse_results(self, nm: nmap.PortScanner) -> List[Dict[str, Any]]:
        parsed_results = []

        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "host_name": nm[host]["hostnames"][0]["name"] if nm[host]["hostnames"] else "",
                "os_name": nm[host].get("osclass", {}).get("osfamily", ""),
                "ports": [],
            }

            for port_info in nm[host]["tcp"].values():
                host_info["ports"].append({
                    "port": port_info["portid"],
                    "state": port_info["state"],
                    "service": port_info["name"],
                })

            parsed_results.append(host_info)

        return parsed_results


class VulnerabilityScanner:
    def __init__(self, server: str, database: str, username: str, password: str):
        self.conn_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}"

    def fetch_ips_and_ports(self) -> List[Tuple[str, str]]:
        conn = pyodbc.connect(self.conn_str)

        cursor = conn.cursor()
        cursor.execute("SELECT ip_address, port FROM vulnerability_view WHERE critical_vulnerability = 1")

        result = [(row.ip_address, str(row.port)) for row in cursor.fetchall()]
        conn.close()

        return result


def main() -> None:
    server = "your_server_address"
    database = "your_database_name"
    username = "your_username"
    password = "your_password"

    vuln_scanner = VulnerabilityScanner(server, database, username, password)
    ips_and_ports = vuln_scanner.fetch_ips_and_ports()

    ip_addresses = list(set([x[0] for x in ips_and_ports]))
    ports = list(set([x[1] for x in ips_and_ports]))

    nmap_scanner = NmapScanner()
    nmap_results = nmap_scanner.scan(ip_addresses, ports)
    parsed_results = nmap_scanner.parse_results(nmap_results)

    db_manager = DatabaseManager("nmap_results.db")

    for host_info in parsed_results:
        db_manager.store_results(host_info["ip"], host_info["host_name"], host_info["os_name"], host_info["ports"])

    db_manager.close()
    print("Results stored in nmap_results.db")

if __name__ == "__main__":
    main()
