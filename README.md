# 🔍 Port Scanner

A fast, multithreaded TCP port scanner with network discovery, service detection, SSL support, banner grabbing, HTML title extraction, and multi-format export — built in pure Python with no external dependencies.

## Features

- **Network scan** — discover live hosts and scan an entire CIDR range (e.g. `192.168.1.0/24`)
- **Host discovery** — optional TCP-based heuristic; firewalls can hide live hosts
- **Multithreaded scanning** — configurable thread count for fast results
- **Service detection** — identifies 40+ common services (SSH, HTTP, FTP, MySQL, RDP, etc.)
- **Banner grabbing** — reads unsolicited banners and uses limited probes for selected protocols
- **HTML title extraction** — fetches the `<title>` tag from HTTP/HTTPS ports
- **SSL/HTTPS support** — verifies certificates before fetching page titles on ports 443/8443
- **Live progress bar** — real-time visual feedback during scanning
- **Custom port list** — scan specific ports with `--ports 22,80,443,3306`
- **Top ports mode** — quickly scan the 46 most common ports with `--top`
- **Multi-format export** — save results as TXT, JSON, or CSV
- **No external dependencies** — pure Python standard library only
- **Bounded concurrency** — threads are limited to 1–1000; network scans are capped at 4096 addresses

## Requirements

- Python 3.6+

## Scan behavior and limitations

- This is a TCP connect scanner. A successful connection means a TCP port accepted a connection; service labels are port-based guesses.
- Host discovery checks a small set of TCP ports. A live host that blocks those ports can be missed. Use a single-host scan to scan even when discovery reports the target as down.
- Only IPv4 CIDR networks are supported. Single-host scans accept IPv4 addresses and hostnames.
- HTTPS title extraction uses normal certificate verification. If a certificate is invalid or issued for a different name, the port can still be reported open, but its title may be unavailable.
- `--output`, `--json`, and `--csv` work in both single-host and network modes.
- Scanning systems requires authorization. Limit concurrency and scan scope to what your network and permission allow.

## Installation

```bash
git clone https://github.com/Nicolastc21/port-scanner.git
cd port-scanner
```

No installation needed — run it directly.

## Usage

```bash
python port_scanner.py <host> [start_port] [end_port] [options]
python port_scanner.py --network <CIDR> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `start_port` | Starting port number | `1` |
| `end_port` | Ending port number | `1024` |
| `--network CIDR` | Scan entire network range (e.g. `192.168.1.0/24`) | disabled |
| `--ports LIST` | Comma-separated ports (e.g. `22,80,443,3306`) | disabled |
| `--top` | Scan only the top 46 common ports | disabled |
| `--threads N` | Number of concurrent threads | `100` |
| `--timeout T` | Connection timeout in seconds | `1.0` |
| `--output FILE` | Save results to TXT file | disabled |
| `--json FILE` | Save results to JSON file | disabled |
| `--csv FILE` | Save results to CSV file | disabled |

## Examples

```bash
# Default scan (ports 1–1024) on a single host
python port_scanner.py 192.168.1.1

# Scan top common ports
python port_scanner.py 192.168.1.1 --top

# Custom port list
python port_scanner.py 192.168.1.1 --ports 22,80,443,3306,5432

# Full range scan with more threads and all export formats
python port_scanner.py 192.168.1.1 1 65535 --threads 300 --output results.txt --json results.json --csv results.csv

# Scan entire local network (discover + scan)
python port_scanner.py --network 192.168.1.0/24 --top

# Network scan with custom ports and JSON report
python port_scanner.py --network 10.0.0.0/24 --ports 22,80,443,3306 --json network_report.json

# Test against Nmap's legal test host
python port_scanner.py scanme.nmap.org 1 1024 --threads 150 --timeout 2
```

## Sample Output

### Single Host
```
============================================================
  Port Scanner — Nicolas-Costin Tanasache
============================================================
  Target  : scanme.nmap.org (45.33.32.156)
  Ports   : 1 - 1024 (1024 ports)
  Threads : 150
  Timeout : 1.0s
  Started : 2026-06-01 18:00:00
============================================================

  [*] Checking if host is alive...
  [+] Host is UP

  [+] 22     SSH         [SSH-2.0-OpenSSH_6.6.1p1]
  [+] 80     HTTP        [HTTP/1.1 200 OK | Title: Go ahead and ScanMe!]
  [████████████████████████████░░] 980/1024 ports | 2 open

============================================================
  Scan complete in 8.42s
  Open ports found: 2

  PORT     SERVICE      BANNER / TITLE
  ------------------------------------------------------------
  22       SSH          SSH-2.0-OpenSSH_6.6.1p1
  80       HTTP         HTTP/1.1 200 OK | Title: Go ahead and ScanMe!
============================================================
```

### Network Scan
```
============================================================
  Mode    : Network Scan
  Ports   : custom (3 ports)
  Threads : 100
============================================================

  [*] Network scan: 192.168.1.0/24
  [*] Total hosts : 254
  [*] Discovering live hosts...

  [+] Host UP: 192.168.1.1
  [+] Host UP: 192.168.1.10
  [+] Host UP: 192.168.1.25

  [*] 3 host(s) alive — starting port scan...

============================================================
  Scanning 192.168.1.1
============================================================
  [+] 80     HTTP        [HTTP/1.1 200 OK]
  [+] 443    HTTPS       [Title: Router Admin Panel]
```

## JSON Report Format

```json
{
    "scan_metadata": {
        "target": "192.168.1.1",
        "ip": "192.168.1.1",
        "timestamp": "2026-06-01T18:00:00",
        "ports_scanned": 1024
    },
    "open_ports": [
        { "port": 80,  "service": "HTTP",  "banner_or_title": "Title: Router Admin" },
        { "port": 443, "service": "HTTPS", "banner_or_title": "HTTP/1.1 200 OK" }
    ]
}
```

## Supported Services

SSH, FTP, Telnet, SMTP, DNS, HTTP, HTTPS, POP3, IMAP, RDP, MySQL, PostgreSQL, MongoDB, Redis, SMB, VNC, LDAP, Elasticsearch, Kubernetes, Jupyter, Flask, WebLogic, and more.

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.  
Only scan systems you own or have **explicit written permission** to test.  
Unauthorized port scanning may be illegal in your jurisdiction.

## Author

**Nicolas-Costin Tanasache**  
[LinkedIn](https://linkedin.com/in/nicolas-costin-tanasache-954348362) • [TryHackMe](https://tryhackme.com/p/nicolas.tanasache) • [GitHub](https://github.com/Nicolastc21)

