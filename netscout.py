#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
import argparse
import ipaddress
import os
import subprocess
import socket
import requests
import concurrent.futures
import time
from collections import defaultdict

DEFAULT_TCP_PORTS = [22, 80, 443, 445, 3389]
console = Console()


def parse_targets(target):
    targets = set()
    if os.path.isfile(target):
        with open(target, 'r') as f:
            lines = f.readlines()
        for line in lines:
            targets.update(parse_targets(line.strip()))
    else:
        try:
            network = ipaddress.ip_network(target, strict=False)
            for ip in network.hosts():
                targets.add(str(ip))
        except ValueError:
            try:
                ipaddress.ip_address(target)
                targets.add(target)
            except ValueError:
                try:
                    resolved = socket.gethostbyname(target)
                    targets.add(resolved)
                except socket.gaierror:
                    console.print(f"[bold red][!] Unable to resolve hostname: {target}[/]")
    return list(targets)


def ping_host(host):
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', '1', host], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def check_tcp_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            return True
    except Exception:
        return False


def check_http(host):
    try:
        response = requests.get(f"http://{host}", timeout=2)
        return response.status_code < 500
    except Exception:
        return False


def format_report(results):
    report = [
        "# Network Segmentation Test Summary",
        "",
        "| Host | ICMP | TCP (Ports) | HTTP |",
        "|------|------|-------------|------|"
    ]
    for host, data in results.items():
        icmp_status = "✅" if data["icmp"] else "❌"
        tcp_summary = ", ".join(f"{port}:✅" if state else f"{port}:❌" for port, state in data["tcp"].items())
        http_status = "✅" if data["http"] else "❌"
        report.append(f"| {host} | {icmp_status} | {tcp_summary} | {http_status} |")
    return "\n".join(report)


def format_subnet_summary(results):
    subnet_results = defaultdict(lambda: {"total": 0, "reachable": 0})
    for host, data in results.items():
        try:
            subnet = str(ipaddress.ip_network(host + '/24', strict=False))
            subnet_results[subnet]["total"] += 1
            if data["icmp"] or any(data["tcp"].values()) or data["http"]:
                subnet_results[subnet]["reachable"] += 1
        except ValueError:
            continue

    summary = [
        "## Subnet Reachability Summary",
        "",
        "| Subnet | Reachable Hosts | Status |",
        "|--------|------------------|--------|"
    ]
    for subnet, stats in subnet_results.items():
        total = stats["total"]
        reachable = stats["reachable"]
        if reachable == 0:
            status = "Unreachable"
        elif reachable < total:
            status = "Partially Reachable"
        else:
            status = "Fully Reachable"
        summary.append(f"| {subnet} | {reachable}/{total} | {status} |")

    return "\n".join(summary)


def enhance_with_ollama(report, ollama_url):
    try:
        response = requests.post(
            f"{ollama_url}/relay",
            headers={"Content-Type": "application/json"},
            json={
                "content": f"Rewrite the following network reachability report in a professional tone for a penetration test:\n\n{report}",
                "stream": False
            }
        )
        if response.ok:
            return response.json().get("response", report)
        else:
            console.print("[bold yellow][!] Ollama enhancement failed. Returning original report.[/]")
            return report
    except Exception as e:
        console.print(f"[bold red][!] Error contacting Ollama server: {e}[/]")
        return report


def test_host(host, ports):
    result = {"icmp": False, "tcp": {}, "http": False}
    result["icmp"] = ping_host(host)
    for port in ports:
        result["tcp"][port] = check_tcp_port(host, port)
    result["http"] = check_http(host)
    return host, result


def display_terminal_table(results, ports):
    table = Table(title="Network Segmentation Reachability Results")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("ICMP", justify="center")
    for port in ports:
        table.add_column(f"TCP {port}", justify="center")
    table.add_column("HTTP", justify="center")

    for host, data in results.items():
        row = [host]
        row.append("✅" if data["icmp"] else "❌")
        for port in ports:
            row.append("✅" if data["tcp"].get(port) else "❌")
        row.append("✅" if data["http"] else "❌")
        table.add_row(*row)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Enhanced Network Segmentation Test Script with Subnet Summary")
    parser.add_argument("target", help="Target IP, CIDR, hostname, or file with list")
    parser.add_argument("--ollama", help="URL of Ollama server (e.g., http://localhost:11434)", default=None)
    parser.add_argument("--ports", nargs="+", type=int, default=DEFAULT_TCP_PORTS,
                        help="List of TCP ports to check (default: 22, 80, 443, 445, 3389)")
    args = parser.parse_args()

    targets = parse_targets(args.target)
    console.print(f"[bold green][+] Total targets parsed: {len(targets)}[/]")

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_host = {executor.submit(test_host, host, args.ports): host for host in targets}
        for future in concurrent.futures.as_completed(future_to_host):
            host, result = future.result()
            results[host] = result

    display_terminal_table(results, args.ports)

    report = format_report(results)
    subnet_summary = format_subnet_summary(results)
    full_report = report + "\n\n" + subnet_summary

    if args.ollama:
        full_report = enhance_with_ollama(full_report, args.ollama)

    console.print("\n[bold blue]--- Begin Markdown Report ---[/]\n")
    print(full_report)
    console.print("\n[bold blue]--- End Markdown Report ---[/]")


if __name__ == "__main__":
    main()
