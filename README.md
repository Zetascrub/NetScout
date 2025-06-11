# NetScout

NetScout is a lightweight Python tool for verifying basic network reachability. It can parse targets from IP addresses, CIDR ranges, hostnames or files and will run several checks in parallel:

* ICMP ping
* TCP connectivity on selected ports
* HTTP and HTTPS requests

Results are displayed in a rich terminal table and a Markdown report is produced. Optionally the report can be enhanced via an Ollama server.

The Markdown report now also includes:

* A summary table listing only hosts that responded to at least one check
* A subnet reachability summary table

## Usage

```bash
python3 netscout.py <target> [--ports 22 80]
```

Targets may be single hosts, CIDR ranges or a file containing one target per line.

## Example

```bash
python3 netscout.py 192.168.1.0/24 --ports 22 80 443
```

This will test each host in the subnet for ICMP reachability, TCP ports 22/80/443 and web accessibility over HTTP and HTTPS.

## Network Visualizer

`netvisualizer.py` performs a quick scan of the local subnets on selected
network interfaces and shows the discovered hosts in a live diagram.

```bash
python3 netvisualizer.py            # interactively choose interfaces
python3 netvisualizer.py --interface eth0 wlan0  # specify interfaces
```

A window will open displaying the network graph and will refresh as hosts
are found. Press <Enter> in the terminal to close the diagram when finished.
