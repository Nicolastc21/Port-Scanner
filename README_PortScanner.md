# 🔍 Port Scanner

A fast, multithreaded TCP port scanner with network discovery, service detection, SSL support, banner grabbing, HTML title extraction, and multi-format export — built in pure Python with no external dependencies.

## Features

- **Network scan** — discover live hosts and scan an entire CIDR range (e.g. `192.168.1.0/24`)
- **Host discovery** — checks if a host is alive before scanning
- **Multithreaded scanning** — configurable thread count for fast results
- **Service detection** — identifies 40+ common services (SSH, HTTP, FTP, MySQL, RDP, etc.)
- **Banner grabbing** — sends protocol-specific probes to retrieve service banners
- **HTML title extraction** — fetches the `<title>` tag from HTTP/HTTPS ports
- **SSL/HTTPS support** — connects correctly on ports 443/8443
- **Live progress bar** — real-time visual feedback during scanning
- **Custom port list** — scan specific ports with `--ports 22,80,443,3306`
- **Top ports mode** — quickly scan the 46 most common ports with `--top`
- **Multi-format export** — save results as TXT, JSON, or CSV
- **No external dependencies** — pure Python standard library only

## Requirements

- Python 3.6+

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
