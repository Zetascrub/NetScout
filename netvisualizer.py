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
from typing import Dict, List, Tuple

import psutil
import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt

# === Globals ===
GRAPH_LOCK = threading.Lock()
GRAPH = nx.Graph()
POS: Dict[str, Tuple[float, float]] = {}
ROOT: str | None = None
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


def traceroute_host(ip: str, max_hops: int = 5) -> List[str]:
    """Return a list of hop IPs toward the destination."""
    hops = []
    for ttl in range(1, max_hops + 1):
        pkt = scapy.IP(dst=ip, ttl=ttl) / scapy.ICMP()
        resp = scapy.sr1(pkt, timeout=1, verbose=0)
        if resp is None:
            break
        hops.append(resp.src)
        if resp.src == ip:
            break
    return hops


def tree_layout(graph: nx.Graph, root: str) -> Dict[str, Tuple[float, float]]:
    """Return hierarchical positions for a tree rooted at `root`."""
    levels: Dict[int, List[str]] = {}
    for node in nx.bfs_tree(graph, root):
        depth = nx.shortest_path_length(graph, root, node)
        levels.setdefault(depth, []).append(node)

    pos: Dict[str, Tuple[float, float]] = {}
    max_width = max(len(nodes) for nodes in levels.values())
    for depth, nodes in levels.items():
        step = max_width / (len(nodes) + 1)
        for i, node in enumerate(nodes):
            pos[node] = ((i + 1) * step - max_width / 2, -float(depth))
    return pos


def scan_subnet(subnet: str, iface: str) -> List[Tuple[str, str | None, List[int]]]:
    """Scan the subnet and return host details."""
    global ROOT
    live_hosts = []
    for ip in ipaddress.IPv4Network(subnet, strict=False).hosts():
        ip_str = str(ip)
        open_ports = [p for p in COMMON_PORTS if port_check(ip_str, p)]
        if ping_host(ip_str) or open_ports:
            hostname = resolve_hostname(ip_str)
            hops = traceroute_host(ip_str)
            live_hosts.append((ip_str, hostname, open_ports))
            with GRAPH_LOCK:
                details = {"ip": ip_str, "hostname": hostname, "open_ports": open_ports}
                GRAPH.add_node(ip_str, label=hostname or ip_str, details=details)
                if hops:
                    if ROOT is None:
                        ROOT = hops[0]
                    prev = None
                    for hop in hops:
                        if hop not in GRAPH:
                            GRAPH.add_node(hop, label=resolve_hostname(hop) or hop,
                                           details={"ip": hop, "hostname": resolve_hostname(hop), "open_ports": []})
                        if prev:
                            GRAPH.add_edge(prev, hop)
                        prev = hop
                    if hops[-1] != ip_str:
                        GRAPH.add_edge(prev, ip_str)
                else:
                    GRAPH.add_edge(iface, ip_str)
    return live_hosts


def update_graph() -> None:
    """Continuously update the matplotlib visualisation with stable positions."""
    global POS
    annotation = None
    while True:
        with GRAPH_LOCK:
            plt.clf()
            if GRAPH.number_of_nodes() > 0 and ROOT:
                POS = tree_layout(GRAPH, ROOT)
                labels = nx.get_node_attributes(GRAPH, "label")
                nodes = list(GRAPH.nodes())
                node_collection = nx.draw_networkx_nodes(GRAPH, POS, nodelist=nodes, node_color="skyblue", node_size=1500)
                node_collection.set_picker(True)
                nx.draw_networkx_edges(GRAPH, POS)
                for node, (x, y) in POS.items():
                    plt.text(x, y - 0.1, labels.get(node, node), ha="center")

                if not hasattr(update_graph, "connected"):
                    def on_pick(event):
                        nonlocal annotation
                        idx = event.ind[0]
                        n = nodes[idx]
                        data = GRAPH.nodes[n].get("details", {})
                        text = f"IP: {data.get('ip', n)}"
                        if data.get("hostname"):
                            text += f"\nHostname: {data['hostname']}"
                        if data.get("open_ports"):
                            ports = ", ".join(str(p) for p in data["open_ports"])
                            text += f"\nOpen ports: {ports}"
                        if annotation:
                            annotation.remove()
                        x, y = POS[n]
                        annotation = plt.annotate(
                            text,
                            xy=(x, y),
                            xytext=(x, y - 0.3),
                            bbox=dict(boxstyle="round,pad=0.5", fc="yellow", alpha=0.5),
                        )
                        plt.draw()

                    plt.gcf().canvas.mpl_connect("pick_event", on_pick)
                    update_graph.connected = True
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
        if ROOT is not None:
            with GRAPH_LOCK:
                GRAPH.add_edge(iface, ROOT)
        print(f"Discovered hosts on {iface}:")
        for host_ip, hostname, ports in hosts:
            port_str = ", ".join(str(p) for p in ports) if ports else "none"
            print(f" - {host_ip} ({hostname or 'No hostname'}) ports: {port_str}")

    input("\nPress Enter to exit and close diagram...\n")


if __name__ == "__main__":
    main()
