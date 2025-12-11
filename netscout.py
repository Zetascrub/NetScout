#!/usr/bin/env python3
"""Enhanced Network Segmentation Test Script.

This tool performs comprehensive network reachability testing including:
- ICMP ping tests
- TCP port connectivity checks
- HTTP/HTTPS service detection
- Subnet reachability analysis
- Optional AI-enhanced reporting via Ollama
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
import argparse
import ipaddress
import os
import subprocess
import socket
import logging
import concurrent.futures

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
import urllib3

# === Configuration ===

@dataclass
class ScanConfig:
    """Configuration for network scanning operations."""
    tcp_ports: List[int] = field(default_factory=lambda: [22, 80, 443, 445, 3389])
    icmp_timeout: int = 1
    tcp_timeout: int = 1
    http_timeout: int = 2
    max_workers: int = 20
    verify_ssl: bool = False
    ollama_url: Optional[str] = None
    verbose: bool = False


@dataclass
class HostResult:
    """Results from scanning a single host."""
    icmp: bool = False
    tcp: Dict[int, bool] = field(default_factory=dict)
    http: bool = False
    https: bool = False

    def is_reachable(self) -> bool:
        """Check if host is reachable via any method."""
        return self.icmp or any(self.tcp.values()) or self.http or self.https


# === Globals ===

console = Console()
logger = logging.getLogger(__name__)


# === Core Functions ===

def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_targets(target: str) -> List[str]:
    """Parse a target into a deterministic ordered list of hosts.

    Args:
        target: Can be an IP address, CIDR notation, hostname, or file path

    Returns:
        List of IP addresses as strings
    """
    collected = []

    def _parse(entry: str) -> None:
        """Recursively parse target entries."""
        if not entry:
            return

        if os.path.isfile(entry):
            logger.debug(f"Reading targets from file: {entry}")
            try:
                with open(entry, "r") as f:
                    for line in f:
                        _parse(line.strip())
            except IOError as e:
                logger.error(f"Failed to read file {entry}: {e}")
                console.print(f"[bold red][!] Error reading file: {entry}[/]")
        else:
            try:
                # Try parsing as network/CIDR
                network = ipaddress.ip_network(entry, strict=False)
                logger.debug(f"Parsed network: {network}")
                for ip in network.hosts():
                    collected.append(str(ip))
            except ValueError:
                try:
                    # Try parsing as single IP
                    ipaddress.ip_address(entry)
                    collected.append(entry)
                    logger.debug(f"Parsed IP: {entry}")
                except ValueError:
                    # Try resolving as hostname
                    try:
                        resolved = socket.gethostbyname(entry)
                        collected.append(resolved)
                        logger.info(f"Resolved {entry} to {resolved}")
                    except socket.gaierror as e:
                        logger.warning(f"Unable to resolve hostname: {entry}")
                        console.print(f"[bold red][!] Unable to resolve hostname: {entry}[/]")

    _parse(target)

    # Remove duplicates while preserving order
    unique_targets = list(dict.fromkeys(collected))
    logger.info(f"Parsed {len(unique_targets)} unique targets")
    return unique_targets


def ping_host(host: str, timeout: int = 1) -> bool:
    """Check if a host responds to ICMP ping.

    Args:
        host: Target IP address or hostname
        timeout: Timeout in seconds

    Returns:
        True if host responds to ping, False otherwise
    """
    try:
        subprocess.check_output(
            ['ping', '-c', '1', '-W', str(timeout), host],
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        logger.debug(f"ICMP success: {host}")
        return True
    except subprocess.CalledProcessError:
        logger.debug(f"ICMP failed: {host}")
        return False
    except subprocess.TimeoutExpired:
        logger.debug(f"ICMP timeout: {host}")
        return False
    except Exception as e:
        logger.error(f"ICMP error for {host}: {e}")
        return False


def check_tcp_port(host: str, port: int, timeout: int = 1) -> bool:
    """Check if a TCP port is open on a host.

    Args:
        host: Target IP address or hostname
        port: TCP port number
        timeout: Connection timeout in seconds

    Returns:
        True if port is open, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            success = result == 0
            if success:
                logger.debug(f"TCP port {port} open on {host}")
            return success
    except socket.gaierror as e:
        logger.debug(f"DNS resolution failed for {host}: {e}")
        return False
    except socket.timeout:
        logger.debug(f"TCP port {port} timeout on {host}")
        return False
    except Exception as e:
        logger.error(f"TCP port check error for {host}:{port}: {e}")
        return False


def check_http_protocol(
    host: str,
    protocol: str = "http",
    timeout: int = 2,
    verify_ssl: bool = False
) -> bool:
    """Check if HTTP/HTTPS service is available on a host.

    Args:
        host: Target IP address or hostname
        protocol: Either 'http' or 'https'
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates

    Returns:
        True if service responds with status code < 500, False otherwise
    """
    url = f"{protocol}://{host}"
    try:
        # Suppress only the specific warning about SSL verification
        with urllib3.warnings.catch_warnings():
            if not verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            success = response.status_code < 500
            if success:
                logger.debug(f"{protocol.upper()} success on {host} (status: {response.status_code})")
            return success
    except requests.exceptions.SSLError as e:
        logger.debug(f"{protocol.upper()} SSL error on {host}: {e}")
        return False
    except requests.exceptions.ConnectionError as e:
        logger.debug(f"{protocol.upper()} connection failed on {host}: {e}")
        return False
    except requests.exceptions.Timeout:
        logger.debug(f"{protocol.upper()} timeout on {host}")
        return False
    except requests.exceptions.RequestException as e:
        logger.debug(f"{protocol.upper()} request error on {host}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected {protocol.upper()} error on {host}: {e}")
        return False


def test_host(
    host: str,
    config: ScanConfig,
    progress: Optional[Progress] = None,
    task_id: Optional[int] = None
) -> Tuple[str, HostResult]:
    """Perform all connectivity tests on a single host.

    Args:
        host: Target IP address
        config: Scan configuration
        progress: Optional Rich progress bar
        task_id: Optional progress task ID

    Returns:
        Tuple of (host, HostResult)
    """
    result = HostResult()

    # ICMP test
    if progress is not None:
        progress.update(task_id, description=f"{host} - ICMP")
    result.icmp = ping_host(host, config.icmp_timeout)
    if progress is not None:
        progress.advance(task_id)

    # TCP port tests
    for port in config.tcp_ports:
        if progress is not None:
            progress.update(task_id, description=f"{host} - TCP {port}")
        result.tcp[port] = check_tcp_port(host, port, config.tcp_timeout)
        if progress is not None:
            progress.advance(task_id)

    # HTTP test
    if progress is not None:
        progress.update(task_id, description=f"{host} - HTTP")
    result.http = check_http_protocol(host, "http", config.http_timeout, config.verify_ssl)
    if progress is not None:
        progress.advance(task_id)

    # HTTPS test
    if progress is not None:
        progress.update(task_id, description=f"{host} - HTTPS")
    result.https = check_http_protocol(host, "https", config.http_timeout, config.verify_ssl)
    if progress is not None:
        progress.advance(task_id)

    return host, result


def format_host_row(host: str, data: HostResult, tcp_ports: List[int]) -> str:
    """Format a single host's results as a markdown table row.

    Args:
        host: IP address
        data: Host scan results
        tcp_ports: List of TCP ports that were scanned

    Returns:
        Markdown table row string
    """
    icmp_status = "✅" if data.icmp else "❌"
    tcp_summary = ", ".join(
        f"{port}:✅" if data.tcp.get(port) else f"{port}:❌"
        for port in tcp_ports
    )
    http_status = "✅" if data.http else "❌"
    https_status = "✅" if data.https else "❌"

    return f"| {host} | {icmp_status} | {tcp_summary} | {http_status} | {https_status} |"


def format_report(results: Dict[str, HostResult], tcp_ports: List[int], order: Optional[List[str]] = None) -> str:
    """Generate a markdown report of all scan results.

    Args:
        results: Dictionary mapping hosts to their scan results
        tcp_ports: List of TCP ports that were scanned
        order: Optional list to preserve host order

    Returns:
        Markdown-formatted report string
    """
    report = [
        "# Network Segmentation Test Summary",
        "",
        "| Host | ICMP | TCP (Ports) | HTTP | HTTPS |",
        "|------|------|-------------|------|-------|"
    ]

    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        report.append(format_host_row(host, data, tcp_ports))

    return "\n".join(report)


def format_reachable_summary(results: Dict[str, HostResult], tcp_ports: List[int], order: Optional[List[str]] = None) -> str:
    """Generate a markdown report of only reachable hosts.

    Args:
        results: Dictionary mapping hosts to their scan results
        tcp_ports: List of TCP ports that were scanned
        order: Optional list to preserve host order

    Returns:
        Markdown-formatted summary string
    """
    lines = [
        "## Reachable Hosts Summary",
        "",
        "| Host | ICMP | TCP (Ports) | HTTP | HTTPS |",
        "|------|------|-------------|------|-------|",
    ]

    host_iter = order if order is not None else results.keys()
    for host in host_iter:
        data = results[host]
        if data.is_reachable():
            lines.append(format_host_row(host, data, tcp_ports))

    if len(lines) == 4:
        lines.append("| _No reachable hosts detected_ | - | - | - | - |")

    return "\n".join(lines)


def format_subnet_summary(results: Dict[str, HostResult]) -> str:
    """Generate a markdown summary of subnet reachability.

    Args:
        results: Dictionary mapping hosts to their scan results

    Returns:
        Markdown-formatted subnet summary string
    """
    subnet_results = defaultdict(lambda: {"total": 0, "reachable": 0})

    for host, data in results.items():
        try:
            subnet = str(ipaddress.ip_network(host + '/24', strict=False))
            subnet_results[subnet]["total"] += 1
            if data.is_reachable():
                subnet_results[subnet]["reachable"] += 1
        except ValueError:
            logger.warning(f"Could not determine subnet for {host}")
            continue

    summary = [
        "## Subnet Reachability Summary",
        "",
        "| Subnet | Reachable Hosts | Status |",
        "|--------|------------------|--------|"
    ]

    for subnet, stats in sorted(subnet_results.items()):
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


def enhance_with_ollama(report: str, ollama_url: str) -> str:
    """Enhance report using Ollama AI service.

    Args:
        report: Original markdown report
        ollama_url: Base URL of Ollama server

    Returns:
        Enhanced report or original if enhancement fails
    """
    try:
        logger.info(f"Contacting Ollama server at {ollama_url}")
        response = requests.post(
            f"{ollama_url}/relay",
            headers={"Content-Type": "application/json"},
            json={
                "content": f"Rewrite the following network reachability report in a professional tone for a penetration test:\n\n{report}",
                "stream": False
            },
            timeout=30
        )

        if response.ok:
            enhanced = response.json().get("response", report)
            logger.info("Successfully enhanced report with Ollama")
            return enhanced
        else:
            logger.warning(f"Ollama returned status {response.status_code}")
            console.print("[bold yellow][!] Ollama enhancement failed. Returning original report.[/]")
            return report

    except requests.exceptions.RequestException as e:
        logger.error(f"Error contacting Ollama server: {e}")
        console.print(f"[bold red][!] Error contacting Ollama server: {e}[/]")
        return report
    except Exception as e:
        logger.error(f"Unexpected error during Ollama enhancement: {e}")
        return report


def display_terminal_table(results: Dict[str, HostResult], tcp_ports: List[int], order: Optional[List[str]] = None) -> None:
    """Display scan results in a Rich table in the terminal.

    Args:
        results: Dictionary mapping hosts to their scan results
        tcp_ports: List of TCP ports that were scanned
        order: Optional list to preserve host order
    """
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
        row.append("✅" if data.icmp else "❌")

        for port in tcp_ports:
            row.append("✅" if data.tcp.get(port) else "❌")

        row.append("✅" if data.http else "❌")
        row.append("✅" if data.https else "❌")
        table.add_row(*row)

    console.print(table)


def main() -> None:
    """Main entry point for the network scanner."""
    parser = argparse.ArgumentParser(
        description="Enhanced Network Segmentation Test Script with Subnet Summary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s 10.0.0.1 --ports 22 80 443
  %(prog)s targets.txt --ollama http://localhost:11434
  %(prog)s example.com --verify-ssl --verbose
        """
    )

    parser.add_argument(
        "target",
        help="Target IP, CIDR, hostname, or file with list of targets"
    )
    parser.add_argument(
        "--ollama",
        help="URL of Ollama server for AI-enhanced reporting (e.g., http://localhost:11434)",
        default=None
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[22, 80, 443, 445, 3389],
        help="List of TCP ports to check (default: 22, 80, 443, 445, 3389)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Maximum number of concurrent workers (default: 20)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1,
        help="Timeout in seconds for ICMP and TCP checks (default: 1)"
    )
    parser.add_argument(
        "--http-timeout",
        type=int,
        default=2,
        help="Timeout in seconds for HTTP/HTTPS checks (default: 2)"
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (default: False)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging output"
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Create scan configuration
    config = ScanConfig(
        tcp_ports=args.ports,
        icmp_timeout=args.timeout,
        tcp_timeout=args.timeout,
        http_timeout=args.http_timeout,
        max_workers=args.workers,
        verify_ssl=args.verify_ssl,
        ollama_url=args.ollama,
        verbose=args.verbose
    )

    # Parse targets
    targets = parse_targets(args.target)

    if not targets:
        console.print("[bold red][!] No valid targets found.[/]")
        return

    console.print(f"[bold green][+] Total targets parsed: {len(targets)}[/]")

    # Initialize results
    results: Dict[str, HostResult] = {}
    total_steps = len(targets) * (1 + len(config.tcp_ports) + 2)

    # Progress bar configuration
    progress_columns = [
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    ]

    # Run scans with progress bar
    with Progress(*progress_columns, console=console) as progress:
        task_id = progress.add_task("Starting reachability tests...", total=total_steps)

        with concurrent.futures.ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            future_to_host = {
                executor.submit(test_host, host, config, progress, task_id): host
                for host in targets
            }

            for future in concurrent.futures.as_completed(future_to_host):
                try:
                    host, result = future.result()
                    results[host] = result
                except Exception as e:
                    failed_host = future_to_host[future]
                    logger.error(f"Failed to scan {failed_host}: {e}")
                    console.print(f"[bold red][!] Error scanning {failed_host}: {e}[/]")

    # Maintain target order in results
    ordered_results = {host: results.get(host, HostResult()) for host in targets}

    # Display terminal table
    display_terminal_table(ordered_results, config.tcp_ports, order=targets)

    # Generate reports
    report = format_report(ordered_results, config.tcp_ports, order=targets)
    reachable_summary = format_reachable_summary(ordered_results, config.tcp_ports, order=targets)
    subnet_summary = format_subnet_summary(ordered_results)
    full_report = f"{report}\n\n{reachable_summary}\n\n{subnet_summary}"

    # Enhance with Ollama if requested
    if config.ollama_url:
        full_report = enhance_with_ollama(full_report, config.ollama_url)

    # Display markdown report
    console.print("\n[bold blue]--- Begin Markdown Report ---[/]\n")
    print(full_report)
    console.print("\n[bold blue]--- End Markdown Report ---[/]")


if __name__ == "__main__":
    main()
