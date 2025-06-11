#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
import argparse
import ipaddress
import os
import subprocess
import socket
import requests
import concurrent.futures
from collections import defaultdict
import urllib3

DEFAULT_TCP_PORTS = [22, 80, 443, 445, 3389]
console = Console()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_targets(target):
    """Parse a target into a deterministic ordered list of hosts."""
    collected = []

    def _parse(entry):
        if os.path.isfile(entry):
            with open(entry, "r") as f:
                for line in f:
                    _parse(line.strip())
        else:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                for ip in network.hosts():
                    collected.append(str(ip))
            except ValueError:
                try:
                    ipaddress.ip_address(entry)
                    collected.append(entry)
                except ValueError:
                    try:
                        resolved = socket.gethostbyname(entry)
                        collected.append(resolved)
                    except socket.gaierror:
                        console.print(f"[bold red][!] Unable to resolve hostname: {entry}[/]")

    _parse(target)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(collected))


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


def check_https(host):
    try:
        response = requests.get(
            f"https://{host}", timeout=2, verify=False
        )
        return response.status_code < 500
    except Exception:
        return False


def format_report(results, order=None):
    report = [
        "# Network Segmentation Test Summary",
        "",
        "| Host | ICMP | TCP (Ports) | HTTP | HTTPS |",
        "|------|------|-------------|------|-------|"
    ]
    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        icmp_status = "✅" if data["icmp"] else "❌"
        tcp_summary = ", ".join(
            f"{port}:✅" if state else f"{port}:❌" for port, state in data["tcp"].items()
        )
        http_status = "✅" if data["http"] else "❌"
        https_status = "✅" if data["https"] else "❌"
        report.append(
            f"| {host} | {icmp_status} | {tcp_summary} | {http_status} | {https_status} |"
        )
    return "\n".join(report)


def format_subnet_summary(results):
    subnet_results = defaultdict(lambda: {"total": 0, "reachable": 0})
    for host, data in results.items():
        try:
            subnet = str(ipaddress.ip_network(host + '/24', strict=False))
            subnet_results[subnet]["total"] += 1
            if (
                data["icmp"]
                or any(data["tcp"].values())
                or data["http"]
                or data["https"]
            ):
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


def format_reachable_summary(results, order=None):
    lines = [
        "## Reachable Hosts Summary",
        "",
        "| Host | ICMP | TCP (Ports) | HTTP | HTTPS |",
        "|------|------|-------------|------|-------|",
    ]
    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        if (
            data["icmp"]
            or any(data["tcp"].values())
            or data["http"]
            or data["https"]
        ):
            icmp_status = "✅" if data["icmp"] else "❌"
            tcp_summary = ", ".join(
                f"{port}:✅" if state else f"{port}:❌" for port, state in data["tcp"].items()
            )
            http_status = "✅" if data["http"] else "❌"
            https_status = "✅" if data["https"] else "❌"
            lines.append(
                f"| {host} | {icmp_status} | {tcp_summary} | {http_status} | {https_status} |"
            )

    if len(lines) == 4:
        lines.append("| _No reachable hosts detected_ | - | - | - | - |")

    return "\n".join(lines)


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


def test_host(host, tcp_ports, progress=None, task_id=None):
    result = {"icmp": False, "tcp": {}, "http": False, "https": False}

    if progress is not None:
        progress.update(task_id, description=f"{host} - ICMP")
    result["icmp"] = ping_host(host)
    if progress is not None:
        progress.advance(task_id)

    for port in tcp_ports:
        if progress is not None:
            progress.update(task_id, description=f"{host} - TCP {port}")
        result["tcp"][port] = check_tcp_port(host, port)
        if progress is not None:
            progress.advance(task_id)


    if progress is not None:
        progress.update(task_id, description=f"{host} - HTTP")
    result["http"] = check_http(host)
    if progress is not None:
        progress.advance(task_id)

    if progress is not None:
        progress.update(task_id, description=f"{host} - HTTPS")
    result["https"] = check_https(host)
    if progress is not None:
        progress.advance(task_id)

    return host, result


def display_terminal_table(results, tcp_ports, order=None):
    table = Table(title="Network Segmentation Reachability Results")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("ICMP", justify="center")
    for port in tcp_ports:
        table.add_column(f"TCP {port}", justify="center")
    table.add_column("HTTP", justify="center")
    table.add_column("HTTPS", justify="center")

    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        row = [host]
        row.append("✅" if data["icmp"] else "❌")
        for port in tcp_ports:
            row.append("✅" if data["tcp"].get(port) else "❌")
        row.append("✅" if data["http"] else "❌")
        row.append("✅" if data["https"] else "❌")
        table.add_row(*row)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Enhanced Network Segmentation Test Script with Subnet Summary")
    parser.add_argument("target", help="Target IP, CIDR, hostname, or file with list")
    parser.add_argument("--ollama", help="URL of Ollama server (e.g., http://localhost:11434)", default=None)
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_TCP_PORTS,
        help="List of TCP ports to check (default: 22, 80, 443, 445, 3389)",
    )
    args = parser.parse_args()

    targets = parse_targets(args.target)
    console.print(f"[bold green][+] Total targets parsed: {len(targets)}[/]")

    results = {}
    total_steps = len(targets) * (1 + len(args.ports) + 2)

    progress_columns = [
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    ]

    with Progress(*progress_columns, console=console) as progress:
        task_id = progress.add_task("Starting reachability tests...", total=total_steps)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_host = {
                executor.submit(test_host, host, args.ports, progress, task_id): host
                for host in targets
            }
            for future in concurrent.futures.as_completed(future_to_host):
                host, result = future.result()
                results[host] = result

    ordered_results = {host: results.get(host) for host in targets}

    display_terminal_table(ordered_results, args.ports, order=targets)

    report = format_report(ordered_results, order=targets)
    reachable_summary = format_reachable_summary(ordered_results, order=targets)
    subnet_summary = format_subnet_summary(ordered_results)
    full_report = report + "\n\n" + reachable_summary + "\n\n" + subnet_summary

    if args.ollama:
        full_report = enhance_with_ollama(full_report, args.ollama)

    console.print("\n[bold blue]--- Begin Markdown Report ---[/]\n")
    print(full_report)
    console.print("\n[bold blue]--- End Markdown Report ---[/]")


if __name__ == "__main__":
    main()
