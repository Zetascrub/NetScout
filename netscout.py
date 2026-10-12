#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
import argparse
import datetime
import ipaddress
import json
import os
import socket
import subprocess
import time
import requests
import concurrent.futures
from collections import defaultdict
import urllib3

DEFAULT_TCP_PORTS = [22, 80, 443, 445, 3389]
DEFAULT_UDP_PORTS = [53, 123, 161]
DEFAULT_TIMEOUT = 1.0
VERSION = "1.1.0"

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Service-specific UDP probes to maximise response rate
UDP_PROBES = {
    53:  (b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'   # DNS TXT version.bind
          b'\x07version\x04bind\x00\x00\x10\x00\x03'),
    123: b'\x1b' + b'\x00' * 47,                                  # NTP client mode 3
    161: (b'\x30\x26\x02\x01\x00\x04\x06public'                   # SNMPv1 GetRequest sysDescr
          b'\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00'
          b'\x02\x01\x00\x30\x0b\x30\x09\x06\x05'
          b'\x2b\x06\x01\x02\x01\x05\x00\x00'),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_ipv6(host):
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def is_reachable(data):
    return (
        data["icmp"]
        or any(v["open"] for v in data["tcp"].values())
        or any(v is True for v in data["udp"].values())
        or data["http"]
        or data["https"]
    )


def _tcp_icon(port_data):
    return "✅" if port_data["open"] else "❌"


def _udp_icon(state):
    if state is True:
        return "✅"
    if state is False:
        return "❌"
    return "⚠️"  # filtered / no response


def _http_url(host, scheme):
    if is_ipv6(host):
        return f"{scheme}://[{host}]"
    return f"{scheme}://{host}"


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_ip_range(entry):
    """Parse 10.0.0.1-50 or 10.0.0.1-10.0.0.50 into a list of IP strings."""
    if '-' not in entry or '/' in entry:
        return None
    left, right = entry.split('-', 1)
    try:
        start = ipaddress.ip_address(left.strip())
        try:
            end = ipaddress.ip_address(right.strip())
        except ValueError:
            base = str(start).rsplit('.', 1)[0]
            end = ipaddress.ip_address(f"{base}.{right.strip()}")
        if int(end) < int(start):
            return None
        ips, cur = [], int(start)
        while cur <= int(end):
            ips.append(str(ipaddress.ip_address(cur)))
            cur += 1
        return ips
    except ValueError:
        return None


def parse_targets(target):
    """Return (ordered_ip_list, host_to_source_subnet_dict)."""
    collected = []
    host_to_subnet = {}

    def _parse(entry):
        if not entry or entry.startswith("#"):
            return
        if os.path.isfile(entry):
            with open(entry) as f:
                for line in f:
                    _parse(line.strip())
            return
        ips = parse_ip_range(entry)
        if ips is not None:
            for ip in ips:
                collected.append(ip)
                host_to_subnet.setdefault(ip, entry)
            return
        try:
            network = ipaddress.ip_network(entry, strict=False)
            subnet_str = str(network)
            for ip in network.hosts():
                ip_str = str(ip)
                collected.append(ip_str)
                host_to_subnet.setdefault(ip_str, subnet_str)
            return
        except ValueError:
            pass
        try:
            ipaddress.ip_address(entry)
            collected.append(entry)
            host_to_subnet.setdefault(entry, entry)
            return
        except ValueError:
            pass
        try:
            resolved = socket.gethostbyname(entry)
            collected.append(resolved)
            host_to_subnet.setdefault(resolved, entry)
        except socket.gaierror:
            console.print(f"[bold red][!] Unable to resolve hostname: {entry}[/]")

    _parse(target)

    seen, unique = set(), []
    for ip in collected:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique, host_to_subnet


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def ping_host(host, timeout=1.0):
    cmd = ['ping6' if is_ipv6(host) else 'ping',
           '-c', '1', '-W', str(max(1, int(timeout))), host]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def check_tcp_port(host, port, timeout=1.0):
    """Return (open: bool, banner: str|None)."""
    family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            banner = None
            try:
                s.settimeout(min(timeout, 0.5))
                raw = s.recv(256)
                text = raw.decode("utf-8", errors="replace").strip()
                banner = text[:120] if text else None
            except Exception:
                pass
            return True, banner
    except Exception:
        return False, None


def check_udp_port(host, port, timeout=1.0):
    """Return True (open), False (ICMP closed), or None (filtered/no response)."""
    family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
    probe = UDP_PROBES.get(port, b'\x00')
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (host, port))
            s.recv(256)
            return True
    except ConnectionRefusedError:
        return False
    except socket.timeout:
        return None
    except Exception:
        return None


def check_http(host, timeout=2.0):
    try:
        r = requests.get(_http_url(host, "http"), timeout=timeout)
        return r.status_code < 500
    except Exception:
        return False


def check_https(host, timeout=2.0):
    try:
        r = requests.get(_http_url(host, "https"), timeout=timeout, verify=False)
        return r.status_code < 500
    except Exception:
        return False


def reverse_dns(host):
    try:
        hostname, _, _ = socket.gethostbyaddr(host)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


# ---------------------------------------------------------------------------
# Per-host test orchestration
# ---------------------------------------------------------------------------

def test_host(host, tcp_ports, udp_ports, timeout, do_rdns, progress=None, task_id=None):
    result = {"icmp": False, "tcp": {}, "udp": {}, "http": False, "https": False, "rdns": None}
    http_timeout = timeout * 2

    if progress:
        progress.update(task_id, description=f"{host} - ICMP")
    result["icmp"] = ping_host(host, timeout)
    if progress:
        progress.advance(task_id)

    for port in tcp_ports:
        if progress:
            progress.update(task_id, description=f"{host} - TCP {port}")
        open_, banner = check_tcp_port(host, port, timeout)
        result["tcp"][port] = {"open": open_, "banner": banner}
        if progress:
            progress.advance(task_id)

    for port in udp_ports:
        if progress:
            progress.update(task_id, description=f"{host} - UDP {port}")
        result["udp"][port] = check_udp_port(host, port, timeout)
        if progress:
            progress.advance(task_id)

    if progress:
        progress.update(task_id, description=f"{host} - HTTP")
    result["http"] = check_http(host, http_timeout)
    if progress:
        progress.advance(task_id)

    if progress:
        progress.update(task_id, description=f"{host} - HTTPS")
    result["https"] = check_https(host, http_timeout)
    if progress:
        progress.advance(task_id)

    if do_rdns and is_reachable(result):
        result["rdns"] = reverse_dns(host)

    return host, result


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------

def display_terminal_table(results, tcp_ports, udp_ports, show_rdns=False, order=None):
    table = Table(title="Network Segmentation Reachability Results")
    table.add_column("Host", style="cyan", no_wrap=True)
    if show_rdns:
        table.add_column("rDNS", style="dim", no_wrap=True)
    table.add_column("ICMP", justify="center")
    for port in tcp_ports:
        table.add_column(f"TCP {port}", justify="center")
    for port in udp_ports:
        table.add_column(f"UDP {port}", justify="center")
    table.add_column("HTTP", justify="center")
    table.add_column("HTTPS", justify="center")

    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        row = [host]
        if show_rdns:
            row.append(data.get("rdns") or "")
        row.append("✅" if data["icmp"] else "❌")
        for port in tcp_ports:
            row.append(_tcp_icon(data["tcp"].get(port, {"open": False})))
        for port in udp_ports:
            row.append(_udp_icon(data["udp"].get(port)))
        row.append("✅" if data["http"] else "❌")
        row.append("✅" if data["https"] else "❌")
        table.add_row(*row, style="green" if is_reachable(data) else "red")

    console.print(table)


# ---------------------------------------------------------------------------
# Markdown report helpers
# ---------------------------------------------------------------------------

def _md_header_row(tcp_ports, udp_ports):
    cols = ["Host", "rDNS", "ICMP"]
    cols += [f"TCP {p}" for p in tcp_ports]
    cols += [f"UDP {p}" for p in udp_ports]
    cols += ["HTTP", "HTTPS"]
    header = "| " + " | ".join(cols) + " |"
    sep    = "| " + " | ".join("---" for _ in cols) + " |"
    return header, sep


def _md_data_row(host, data, tcp_ports, udp_ports):
    cells = [host, data.get("rdns") or ""]
    cells.append("✅" if data["icmp"] else "❌")
    cells += [_tcp_icon(data["tcp"].get(p, {"open": False})) for p in tcp_ports]
    cells += [_udp_icon(data["udp"].get(p)) for p in udp_ports]
    cells += ["✅" if data["http"] else "❌", "✅" if data["https"] else "❌"]
    return "| " + " | ".join(cells) + " |"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def format_report_header(targets, reachable_count, start_time, end_time,
                         operator=None, note=None):
    total = len(targets)
    pct = (reachable_count / total * 100) if total else 0
    ts = datetime.datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S")
    rows = [
        f"| Date | {ts} |",
        f"| Duration | {end_time - start_time:.1f}s |",
        f"| Tool version | NetScout v{VERSION} |",
        f"| Hosts scanned | {total} |",
        f"| Reachable | {reachable_count}/{total} ({pct:.1f}%) |",
    ]
    if operator:
        rows.append(f"| Operator | {operator} |")
    if note:
        rows.append(f"| Note | {note} |")
    return "\n".join([
        "# Network Segmentation Test Report", "",
        "| Field | Value |", "|-------|-------|",
        *rows,
    ])


def format_reachable_summary(results, tcp_ports, udp_ports, order=None):
    header, sep = _md_header_row(tcp_ports, udp_ports)
    lines = ["## Reachable Hosts", "", header, sep]
    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        if is_reachable(data):
            lines.append(_md_data_row(host, data, tcp_ports, udp_ports))
    if len(lines) == 4:
        lines.append("| _No reachable hosts detected_ | - | - | - | - |")
    return "\n".join(lines)


def format_banner_section(results, tcp_ports, order=None):
    lines = ["## Service Banners", ""]
    found = False
    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        banners = {p: info["banner"] for p, info in data["tcp"].items() if info["banner"]}
        if banners:
            found = True
            label = f"{host} ({data['rdns']})" if data.get("rdns") else host
            lines.append(f"### {label}")
            for port, banner in banners.items():
                lines.append(f"- **TCP {port}:** `{banner}`")
            lines.append("")
    if not found:
        lines.append("_No banners captured._")
    return "\n".join(lines)


def format_subnet_summary(results, host_to_subnet):
    subnet_stats = defaultdict(lambda: {"total": 0, "reachable": 0})
    for host, data in results.items():
        subnet = host_to_subnet.get(host, host)
        subnet_stats[subnet]["total"] += 1
        if is_reachable(data):
            subnet_stats[subnet]["reachable"] += 1

    lines = [
        "## Subnet Reachability Summary", "",
        "| Subnet | Reachable Hosts | Status |",
        "|--------|-----------------|--------|",
    ]
    for subnet, stats in subnet_stats.items():
        total, reachable = stats["total"], stats["reachable"]
        if reachable == 0:
            status = "Unreachable"
        elif reachable < total:
            status = "Partially Reachable"
        else:
            status = "Fully Reachable"
        lines.append(f"| {subnet} | {reachable}/{total} | {status} |")
    return "\n".join(lines)


def format_full_results(results, tcp_ports, udp_ports, order=None):
    header, sep = _md_header_row(tcp_ports, udp_ports)
    lines = ["## Full Host Results", "", header, sep]
    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        lines.append(_md_data_row(host, results[host], tcp_ports, udp_ports))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def build_json_output(results, host_to_subnet, targets, start_time, end_time, args):
    reachable = sum(1 for h in targets if is_reachable(results[h]))
    return {
        "meta": {
            "timestamp": datetime.datetime.fromtimestamp(start_time).isoformat(),
            "duration_seconds": round(end_time - start_time, 2),
            "tool_version": VERSION,
            "targets_scanned": len(targets),
            "reachable": reachable,
            "operator": getattr(args, "operator", None),
            "note": getattr(args, "note", None),
        },
        "hosts": {
            host: {
                "subnet": host_to_subnet.get(host),
                "rdns": results[host].get("rdns"),
                "reachable": is_reachable(results[host]),
                "icmp": results[host]["icmp"],
                "tcp": {
                    str(port): {"open": info["open"], "banner": info["banner"]}
                    for port, info in results[host]["tcp"].items()
                },
                "udp": {
                    str(port): {
                        "state": "open" if state is True else
                                 "closed" if state is False else "filtered"
                    }
                    for port, state in results[host]["udp"].items()
                },
                "http": results[host]["http"],
                "https": results[host]["https"],
            }
            for host in targets
        },
    }


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

def enhance_with_ollama(report, ollama_url):
    try:
        response = requests.post(
            f"{ollama_url}/relay",
            headers={"Content-Type": "application/json"},
            json={
                "content": (
                    "Rewrite the following network reachability report in a "
                    f"professional tone for a penetration test:\n\n{report}"
                ),
                "stream": False,
            },
        )
        if response.ok:
            return response.json().get("response", report)
        console.print("[bold yellow][!] Ollama enhancement failed. Returning original report.[/]")
        return report
    except Exception as e:
        console.print(f"[bold red][!] Error contacting Ollama server: {e}[/]")
        return report


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"NetScout v{VERSION} — Network Segmentation Test Script"
    )
    parser.add_argument("target", help="IP, CIDR, range (10.0.0.1-50), hostname, or file")
    parser.add_argument("--ollama", default=None, metavar="URL",
                        help="Ollama server URL for AI report enhancement")
    parser.add_argument("--output", metavar="FILE", help="Write markdown report to file")
    parser.add_argument("--output-json", metavar="FILE", help="Write JSON report to file")
    parser.add_argument(
        "--ports", nargs="+", type=int, default=DEFAULT_TCP_PORTS,
        metavar="PORT", help="TCP ports (default: 22 80 443 445 3389)",
    )
    parser.add_argument(
        "--udp-ports", nargs="*", type=int, default=DEFAULT_UDP_PORTS,
        metavar="PORT", help="UDP ports (default: 53 123 161); pass no args to disable",
    )
    parser.add_argument(
        "--exclude", nargs="+", default=[], metavar="TARGET",
        help="IPs, CIDRs, ranges, or files to exclude",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help="Base timeout in seconds for ICMP/TCP/UDP (HTTP uses 2x, default: 1.0)",
    )
    parser.add_argument(
        "--workers", type=int, default=20,
        help="Concurrent scan threads (default: 20)",
    )
    parser.add_argument("--rdns", action="store_true",
                        help="Reverse-resolve hostnames for reachable hosts")
    parser.add_argument("--operator", default=None, help="Operator name for report metadata")
    parser.add_argument("--note", default=None, help="Free-text note appended to report metadata")
    args = parser.parse_args()

    targets, host_to_subnet = parse_targets(args.target)

    if args.exclude:
        exclude_ips = set()
        for ex in args.exclude:
            exc, _ = parse_targets(ex)
            exclude_ips.update(exc)
        before = len(targets)
        targets = [t for t in targets if t not in exclude_ips]
        host_to_subnet = {k: v for k, v in host_to_subnet.items() if k not in exclude_ips}
        console.print(f"[bold yellow][~] Excluded {before - len(targets)} hosts[/]")

    udp_ports = args.udp_ports if args.udp_ports is not None else []
    console.print(f"[bold green][+] Total targets: {len(targets)}[/]")

    results = {}
    steps_per_host = 1 + len(args.ports) + len(udp_ports) + 2

    progress_columns = [
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    ]

    start_time = time.time()
    with Progress(*progress_columns, console=console) as progress:
        task_id = progress.add_task("Starting...", total=len(targets) * steps_per_host)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    test_host, host, args.ports, udp_ports,
                    args.timeout, args.rdns, progress, task_id
                ): host
                for host in targets
            }
            for future in concurrent.futures.as_completed(futures):
                host, result = future.result()
                results[host] = result
    end_time = time.time()

    ordered = {host: results[host] for host in targets}
    reachable_count = sum(1 for d in ordered.values() if is_reachable(d))

    display_terminal_table(ordered, args.ports, udp_ports,
                           show_rdns=args.rdns, order=targets)
    console.print(f"\n[bold green][+] Reachable: {reachable_count}/{len(targets)}[/]")

    full_report = "\n\n".join([
        format_report_header(targets, reachable_count, start_time, end_time,
                             args.operator, args.note),
        format_reachable_summary(ordered, args.ports, udp_ports, order=targets),
        format_banner_section(ordered, args.ports, order=targets),
        format_subnet_summary(ordered, host_to_subnet),
        format_full_results(ordered, args.ports, udp_ports, order=targets),
    ])

    if args.ollama:
        full_report = enhance_with_ollama(full_report, args.ollama)

    console.print("\n[bold blue]--- Begin Markdown Report ---[/]\n")
    print(full_report)
    console.print("\n[bold blue]--- End Markdown Report ---[/]")

    if args.output:
        with open(args.output, "w") as f:
            f.write(full_report)
        console.print(f"[bold green][+] Markdown report written to {args.output}[/]")

    if args.output_json:
        json_data = build_json_output(ordered, host_to_subnet, targets,
                                      start_time, end_time, args)
        with open(args.output_json, "w") as f:
            json.dump(json_data, f, indent=2)
        console.print(f"[bold green][+] JSON report written to {args.output_json}[/]")


if __name__ == "__main__":
    main()
