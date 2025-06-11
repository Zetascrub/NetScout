#!/usr/bin/env python3
"""Interactive network scanner and live visualizer.

This tool enumerates network interfaces and allows the user to
scan subnets reachable from selected interfaces. Discovered hosts
are displayed in a dynamic network diagram using matplotlib.
"""

import argparse
import ipaddress
import socket
import threading
import time
from typing import Dict, List, Tuple

import psutil
import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt

# === Globals ===
GRAPH_LOCK = threading.Lock()
GRAPH = nx.Graph()
COMMON_PORTS = [22, 80, 443]


def get_interfaces() -> Dict[str, List[str]]:
    """Return a mapping of interface names to IPv4 addresses."""
    interfaces = psutil.net_if_addrs()
    ipv4_ifaces = {}
    for iface, details in interfaces.items():
        addrs = [addr.address for addr in details if addr.family == socket.AF_INET]
        if addrs:
            ipv4_ifaces[iface] = addrs
    return ipv4_ifaces


def choose_interface(interfaces: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """Prompt user to select one or more interfaces."""
    print("Available interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(f"{idx}. {iface} - {interfaces[iface][0]}")
    choice = input("Select interface(s) by number (comma-separated or 'all'): ").strip()

    if choice.lower() == "all":
        return [(iface, addrs[0]) for iface, addrs in interfaces.items()]

    indices = [int(x) - 1 for x in choice.split(",")]
    selected = [list(interfaces.items())[i] for i in indices]
    return [(iface, addrs[0]) for iface, addrs in selected]


def resolve_hostname(ip: str) -> str | None:
    """Try to resolve the hostname for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def ping_host(ip: str) -> bool:
    """Return True if the host responds to ICMP."""
    resp = scapy.sr1(scapy.IP(dst=ip) / scapy.ICMP(), timeout=1, verbose=0)
    return resp is not None


def port_check(ip: str, port: int) -> bool:
    """Check connectivity to a TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def scan_subnet(subnet: str, iface: str) -> List[Tuple[str, str | None]]:
    """Scan the subnet and return a list of (ip, hostname) tuples for live hosts."""
    live_hosts = []
    for ip in ipaddress.IPv4Network(subnet, strict=False).hosts():
        ip_str = str(ip)
        if ping_host(ip_str) or any(port_check(ip_str, p) for p in COMMON_PORTS):
            hostname = resolve_hostname(ip_str)
            live_hosts.append((ip_str, hostname))
            with GRAPH_LOCK:
                GRAPH.add_node(ip_str, label=hostname or "Unknown")
                GRAPH.add_edge(iface, ip_str)
    return live_hosts


def update_graph() -> None:
    """Continuously update the matplotlib visualisation."""
    while True:
        with GRAPH_LOCK:
            plt.clf()
            pos = nx.spring_layout(GRAPH)
            labels = nx.get_node_attributes(GRAPH, "label")
            nx.draw(GRAPH, pos, with_labels=True, node_color="skyblue", node_size=1500)
            nx.draw_networkx_labels(GRAPH, pos, labels)
        plt.pause(2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live subnet visualiser and scanner")
    parser.add_argument("--interface", nargs="*", help="Interface(s) to scan")
    args = parser.parse_args()

    interfaces = get_interfaces()
    if not interfaces:
        print("No network interfaces with IPv4 addresses found.")
        return

    if args.interface:
        selected = [(iface, interfaces[iface][0]) for iface in args.interface if iface in interfaces]
    else:
        selected = choose_interface(interfaces)

    plt.ion()
    thread = threading.Thread(target=update_graph, daemon=True)
    thread.start()

    for iface, ip in selected:
        subnet = ip + "/24"  # Basic assumption; adjust as needed
        print(f"\nScanning subnet {subnet} on {iface}...")
        with GRAPH_LOCK:
            GRAPH.add_node(iface, label=f"Interface: {iface}")
        hosts = scan_subnet(subnet, iface)
        print(f"Discovered hosts on {iface}:")
        for host_ip, hostname in hosts:
            print(f" - {host_ip} ({hostname or 'No hostname'})")

    input("\nPress Enter to exit and close diagram...\n")


if __name__ == "__main__":
    main()
