# NetScout

NetScout is a lightweight Python tool for verifying basic network reachability. It can parse targets from IP addresses, CIDR ranges, hostnames or files and will run several checks in parallel:

* ICMP ping
* TCP connectivity on selected ports
* UDP probes on selected ports
* HTTP and HTTPS requests

Results are displayed in a rich terminal table and a Markdown report is produced. Optionally the report can be enhanced via an Ollama server.

## Usage

```bash
python3 netscout.py <target> [--ports 22 80] [--udp-ports 53 123]
```

Targets may be single hosts, CIDR ranges or a file containing one target per line.

## Example

```bash
python3 netscout.py 192.168.1.0/24 --ports 22 80 443 --udp-ports 53
```

This will test each host in the subnet for ICMP reachability, TCP ports 22/80/443, UDP port 53 and web accessibility over HTTP and HTTPS.
