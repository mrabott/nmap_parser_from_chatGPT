#!/usr/bin/python3

import nmap
import sqlite3
import sys
from typing import List, Dict, Any


# Database setup
def create_database() -> sqlite3.Connection:
    """Create SQLite database and tables to store scan results."""

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


def store_results(conn: sqlite3.Connection, ip: str, host_name: str, os_name: str, ports: List[Dict[str, Any]]) -> None:
    """Store parsed nmap scan results in the SQLite database."""
    c = conn.cursor()
    SQL_CMD = f"INSERT INTO hosts (ip_address, host_name, os_name) VALUES ('{ip}', '{host_name}', '{os_name}')"
    print(SQL_CMD)
    c.execute(SQL_CMD)
    host_id = c.lastrowid

    for port in ports:
        SQL_CMD = f"INSERT INTO ports (host_id, port_number, state, service_name) VALUES ('{host_id}', '{port['port']}', '{port['state']}','{port['service']}')"
        c.execute(SQL_CMD,)
        print(SQL_CMD)
    conn.commit()


# Nmap scan and parsing
def nmap_scan(ip_addresses: List[str], ports: List[str]) -> nmap.PortScanner:
    """Perform nmap scan on the given IP addresses and ports."""

    nm = nmap.PortScanner()
    scan_range = ",".join(ip_addresses)
    port_range = ",".join(ports)

    nm.scan(scan_range, port_range, arguments="-O")
    return nm


def parse_nmap_results(nmap_results: nmap.PortScanner) -> List[Dict[str, Any]]:
    """Parse nmap scan results and return a list of dictionaries containing the required information."""

    parsed_results = []

    for host in nmap_results.all_hosts():
        host_info = {
            "ip": host,
            "host_name": nmap_results[host]["hostnames"][0]["name"] if nmap_results[host]["hostnames"] else "",
            "os_name": nmap_results[host].get("osclass", {}).get("osfamily", ""),
            "ports": [],
        }

        for port in nmap_results[host]["tcp"]:
            port_info=nmap_results[host]['tcp'][port]

            host_info["ports"].append({
                "port": port,
                "state": port_info["state"],
                "service": port_info["name"],
            })

        parsed_results.append(host_info)

    return parsed_results

# Main function
def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: nmap_parser.py <comma-separated ip addresses> <comma-separated ports>")
        sys.exit(1)

    ip_addresses = sys.argv[1].split(",")
    ports = sys.argv[2].split(",")

    nmap_results = nmap_scan(ip_addresses, ports)
    parsed_results = parse_nmap_results(nmap_results)
    #print (parsed_results)
    conn = create_database()

    for host_info in parsed_results:
        store_results(conn, host_info["ip"], host_info["host_name"], host_info["os_name"], host_info["ports"])

    conn.close()
    print("Results stored in nmap_results.db")


if __name__ == "__main__":
    main()
