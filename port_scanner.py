import socket
import threading
import argparse
import sys
import re
import ssl
import json
import csv
import ipaddress
from datetime import datetime, timezone
from queue import Queue, Empty
from typing import Optional, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from threading import Lock

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
    119: "NNTP", 123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub", 631: "IPP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2181: "Zookeeper", 3000: "Dev-Server", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5000: "Flask", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch",
    9300: "Elasticsearch", 27017: "MongoDB", 27018: "MongoDB"
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 194, 389,
    443, 445, 465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1521,
    1723, 2049, 2181, 3000, 3306, 3389, 4444, 5000, 5432, 5900,
    6379, 6443, 7001, 8000, 8080, 8443, 8888, 9200, 9300, 27017
]

PROBES = {
    22: b"SSH-2.0-Scanner\r\n",
    25: b"EHLO scanner\r\n",
    110: b"USER test\r\n",
    143: b"A001 CAPABILITY\r\n",
    21: b"",
    3306: b"",
}

HTTP_PORTS = {80, 8000, 8080, 8888, 3000, 5000, 7001}
HTTPS_PORTS = {443, 8443}

class ScanState:
    def __init__(self, total):
        self.lock = Lock()
        self.print_lock = Lock()
        self.results = []
        self.scanned = 0
        self.total = total


def get_service(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    try:
        probe = PROBES.get(port, b"")
        if probe:
            sock.send(probe)
        raw = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        line = raw.split("\n")[0].strip()
        return line[:70] if line else None
    except Exception:
        return None


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.parts.append(data)


def get_web_title(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        family, socktype, proto, _, address = addresses[0]
        with socket.socket(family, socktype, proto) as raw:
            raw.settimeout(timeout)
            if port in HTTPS_PORTS:
                # Keep certificate verification enabled; title extraction is optional.
                with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as sock:
                    sock.connect(address)
                    return _read_web_title(sock, host, timeout)
            raw.connect(address)
            return _read_web_title(raw, host, timeout)
    except (OSError, ssl.SSLError, ValueError):
        return None


def _read_web_title(sock, host, timeout):
    sock.sendall((f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: PortScanner/3.0\r\nConnection: close\r\n\r\n").encode("utf-8"))
    response = bytearray()
    while len(response) < 50000:
        try:
            chunk = sock.recv(min(4096, 50000 - len(response)))
        except socket.timeout:
            break
        if not chunk:
            break
        response.extend(chunk)
    body = bytes(response).split(b"\r\n\r\n", 1)[-1].decode("utf-8", errors="replace")
    parser = TitleParser()
    parser.feed(body)
    title = re.sub(r"\s+", " ", " ".join(parser.parts)).strip()
    return f"Title: {title[:50]}" if title else None


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str], Optional[str]]:
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                service = get_service(port)
                banner = grab_banner(sock, port)
                if port in HTTP_PORTS or port in HTTPS_PORTS:
                    title = get_web_title(host, port, timeout)
                    if title:
                        banner = f"{banner} | {title}" if banner else title
                return (port, True, service, banner)
    except OSError:
        pass
    return (port, False, None, None)


def show_progress(current: int, total: int, open_count: int):
    if total <= 0:
        return
    pct = current / total
    bar = int(pct * 30)
    line = (f"\r  [{'█' * bar}{'░' * (30 - bar)}] "
            f"{current}/{total} ports  |  {open_count} open")
    sys.stdout.write(line)
    sys.stdout.flush()


def worker(host: str, queue: Queue, timeout: float, state: ScanState):
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            break

        port_num, is_open, service, banner = scan_port(host, port, timeout)

        with state.lock:
            state.scanned += 1
            current = state.scanned
        if is_open:
            with state.lock:
                state.results.append((port_num, service, banner))
                open_count = len(state.results)
            with state.print_lock:
                sys.stdout.write("\r" + " " * 75 + "\r")
                banner_str = f"  [{banner}]" if banner else ""
                print(f"  [+] {port_num:<6} {service:<12}{banner_str}")
                show_progress(current, state.total, open_count)
        else:
            with state.print_lock:
                show_progress(current, state.total, len(state.results))

        queue.task_done()


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}")
        sys.exit(1)


def save_txt(filepath: str, host: str, ip: str, args, scan_results):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  Port Scanner — Nicolas-Costin Tanasache\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Target  : {host} ({ip})\n")
        f.write(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        if scan_results:
            f.write(f"  {'PORT':<8} {'SERVICE':<12} BANNER / TITLE\n")
            f.write(f"  {'-' * 60}\n")
            for port, service, banner in sorted(scan_results):
                b = banner if banner else "-"
                f.write(f"  {port:<8} {service:<12} {b}\n")


def save_json(filepath: str, host: str, ip: str, args, scan_results, scanned_count):
    data = {
        "scan_metadata": {
            "target": host,
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ports_scanned": scanned_count,
            "timeout_seconds": args.timeout,
            "threads": args.threads
        },
        "open_ports": [
            {"port": p, "service": s, "banner_or_title": b}
            for p, s, b in sorted(scan_results)
        ]
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def save_csv(filepath: str, scan_results):
    with open(filepath, "w", newline="", encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Service", "Banner_Title"])
        for p, s, b in sorted(scan_results):
            writer.writerow([p, s, b or ""])


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    for port in [80, 443, 22, 445, 3389]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
            sock.close()
        except socket.error:
            pass
    return False


def get_hosts_from_cidr(network: str) -> List[str]:
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError as e:
        print(f"[!] Invalid network: {e}")
        sys.exit(1)


def scan_network(network: str, ports: List[int], args) -> None:
    hosts = get_hosts_from_cidr(network)
    total_hosts = len(hosts)

    print(f"\n  [*] Network scan: {network}")
    print(f"  [*] Total hosts : {total_hosts}")
    print(f"  [*] Discovering live hosts (TCP heuristic, timeout: {args.timeout}s)...\n")

    live_hosts = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(ping_host, ip, args.timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                live_hosts.append(ip)
                print(f"  [+] Host UP: {ip}")

    if not live_hosts:
        print("\n  [!] No live hosts found.")
        return

    live_hosts.sort(key=lambda x: list(map(int, x.split("."))))
    print(f"\n  [*] {len(live_hosts)} host(s) alive — starting port scan...\n")

    all_results = {}

    for ip in live_hosts:
        state = ScanState(len(ports))

        print("=" * 60)
        print(f"  Scanning {ip}")
        print("=" * 60)

        queue = Queue()
        for p in ports:
            queue.put(p)

        threads_list = []
        for _ in range(min(args.threads, len(ports))):
            t = threading.Thread(target=worker, args=(ip, queue, args.timeout, state))
            t.daemon = True
            t.start()
            threads_list.append(t)
        for t in threads_list:
            t.join()

        print(f"\n\n  Open ports: {len(state.results)}")
        if state.results:
            print(f"  {'PORT':<8} {'SERVICE':<12} BANNER / TITLE")
            print(f"  {'-' * 50}")
            for port, service, banner in sorted(state.results):
                b = banner if banner else "-"
                print(f"  {port:<8} {service:<12} {b[:45]}")
        print()

        all_results[ip] = list(state.results)

    if args.json:
        data = {
            "scan_type": "network",
            "network": network,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ports_scanned_per_host": len(ports),
            "timeout_seconds": args.timeout,
            "threads": args.threads,
            "live_hosts": len(live_hosts),
            "results": {
                ip: [{"port": p, "service": s, "banner": b}
                     for p, s, b in sorted(all_results[ip])]
                for ip in all_results
            }
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"  [+] Network report saved: {args.json}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(f"Network scan: {network}\nUTC timestamp: {datetime.now(timezone.utc).isoformat()}\n")
            for ip, entries in all_results.items():
                out.write(f"\n{ip}\n" + "-" * 50 + "\n")
                for p, service, banner in sorted(entries):
                    out.write(f"{p:<8} {service:<12} {banner or '-'}\n")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(["Host", "Port", "Service", "Banner_Title"])
            for ip, entries in all_results.items():
                for p, service, banner in sorted(entries):
                    writer.writerow([ip, p, service, banner or ""])


def main():

    parser = argparse.ArgumentParser(
        description="Multithreaded TCP Port Scanner with Network Discovery",
        epilog=(
            "Examples:\n"
            "  python port_scanner.py 192.168.1.1\n"
            "  python port_scanner.py scanme.nmap.org 1 1024 --threads 150\n"
            "  python port_scanner.py 192.168.1.1 --ports 22,80,443,3306\n"
            "  python port_scanner.py --network 192.168.1.0/24 --top\n"
            "  python port_scanner.py --network 10.0.0.0/24 --ports 22,80,443 --json out.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("host", nargs="?", default=None, help="Target host (IP or hostname)")
    parser.add_argument("start_port", nargs="?", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("end_port", nargs="?", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--network", type=str, default=None, help="CIDR range to scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated port list (e.g. 22,80,443)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
    parser.add_argument("--output", type=str, default=None, help="Save results to TXT file")
    parser.add_argument("--json", type=str, default=None, help="Save results to JSON file")
    parser.add_argument("--csv", type=str, default=None, help="Save results to CSV file")
    parser.add_argument("--top", action="store_true", help="Scan only the top common ports")
    args = parser.parse_args()

    if args.threads < 1 or args.threads > 1000:
        parser.error("--threads must be between 1 and 1000")
    if not 0.05 <= args.timeout <= 300:
        parser.error("--timeout must be between 0.05 and 300 seconds")
    if args.network and args.host:
        parser.error("--network cannot be combined with a host")
    if args.host and (args.start_port != 1 or args.end_port != 1024) and (args.ports or args.top):
        parser.error("positional port range cannot be combined with --ports or --top")

    if args.ports:
        try:
            if not args.ports.strip():
                raise ValueError
            port_list = sorted(set(int(p.strip()) for p in args.ports.split(",")))
            if any(p < 1 or p > 65535 for p in port_list):
                raise ValueError
        except ValueError:
            print("[!] Invalid --ports value. Use comma-separated numbers between 1-65535.")
            sys.exit(1)
        label = f"custom ({len(port_list)} ports)"
    elif args.top:
        port_list = sorted(TOP_PORTS)
        label = f"top {len(port_list)} common ports"
    else:
        if not (1 <= args.start_port <= args.end_port <= 65535):
            print("[!] Invalid port range. Use values between 1 and 65535.")
            sys.exit(1)
        port_list = list(range(args.start_port, args.end_port + 1))
        label = f"{args.start_port} - {args.end_port}"

    if args.network:
        try:
            net = ipaddress.IPv4Network(args.network, strict=False)
            if net.num_addresses > 4096:
                parser.error("network scans are limited to 4096 addresses")
        except ValueError as exc:
            parser.error(f"invalid network: {exc}")
        print("=" * 60)
        print("  Port Scanner — Nicolas-Costin Tanasache")
        print("=" * 60)
        print(f"  Mode    : Network Scan")
        print(f"  Ports   : {label}")
        print(f"  Threads : {args.threads}")
        print(f"  Timeout : {args.timeout}s")
        print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        scan_network(args.network, port_list, args)
        return

    if not args.host:
        parser.print_help()
        sys.exit(1)

    ip = resolve_host(args.host)
    total_ports = len(port_list)
    state = ScanState(total_ports)

    print("=" * 60)
    print("  Port Scanner — Nicolas-Costin Tanasache")
    print("=" * 60)
    print(f"  Target  : {args.host} ({ip})")
    print(f"  Ports   : {label}")
    print(f"  Threads : {min(args.threads, total_ports)}")
    print(f"  Timeout : {args.timeout}s")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    print("  [*] Checking if host is alive...")
    if not ping_host(ip, args.timeout):
        print("  [!] Host appears offline or blocking connections — scanning anyway...\n")
    else:
        print("  [+] Host is UP\n")

    queue = Queue()
    for p in port_list:
        queue.put(p)

    start_time = datetime.now()

    threads = []
    for _ in range(min(args.threads, total_ports)):
        t = threading.Thread(target=worker, args=(ip, queue, args.timeout, state))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    duration = (datetime.now() - start_time).total_seconds()

    print("\n\n" + "=" * 60)
    print(f"  Scan complete in {duration:.2f}s")
    print(f"  Open ports found: {len(state.results)}")

    if state.results:
        print(f"\n  {'PORT':<8} {'SERVICE':<12} BANNER / TITLE")
        print(f"  {'-' * 60}")
        for port, service, banner in sorted(state.results):
            b = banner if banner else "-"
            print(f"  {port:<8} {service:<12} {b[:55]}")
    print("=" * 60)

    if args.output:
        save_txt(args.output, args.host, ip, args, state.results)
        print(f"  [+] Saved TXT  : {args.output}")
    if args.json:
        save_json(args.json, args.host, ip, args, state.results, state.scanned)
        print(f"  [+] Saved JSON : {args.json}")
    if args.csv:
        save_csv(args.csv, state.results)
        print(f"  [+] Saved CSV  : {args.csv}")

if __name__ == "__main__":
    main()

