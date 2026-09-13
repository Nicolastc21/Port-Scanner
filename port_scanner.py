import socket
import threading
import argparse
import sys
import re
import ssl
import json
import csv
import ipaddress
from datetime import datetime
from queue import Queue, Empty
from typing import Optional, Tuple, List

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

print_lock = threading.Lock()
counter_lock = threading.Lock()
results = []
scanned = 0
total_ports = 0


def get_service(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    try:
        probe = PROBES.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
        if probe:
            sock.send(probe)
        raw = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        line = raw.split("\n")[0].strip()
        return line[:70] if line else None
    except Exception:
        return None


def get_web_title(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if port in HTTPS_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PortScanner/3.0\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        while True:
            data = sock.recv(2048)
            if not data:
                break
            response += data
            if b"</title>" in response.lower() or len(response) > 50000:
                break
        sock.close()

        html = response.decode('utf-8', errors='ignore')
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            title = re.sub(r'\s+', ' ', title)
            return f"Title: {title[:50]}"
    except Exception:
        return None
    return None


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str], Optional[str]]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            service = get_service(port)
            banner = grab_banner(sock, port)
            sock.close()

            if port in HTTP_PORTS or port in HTTPS_PORTS:
                title = get_web_title(host, port, timeout)
                if title:
                    banner = f"{banner} | {title}" if banner else title

            return (port, True, service, banner)
        sock.close()
    except socket.error:
        pass
    return (port, False, None, None)


def show_progress(current: int, total: int, open_count: int):
    pct = current / total
    bar = int(pct * 30)
    line = (f"\r  [{'█' * bar}{'░' * (30 - bar)}] "
            f"{current}/{total} ports  |  {open_count} open")
    sys.stdout.write(line)
    sys.stdout.flush()


def worker(host: str, queue: Queue, timeout: float):
    global scanned
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            break

        port_num, is_open, service, banner = scan_port(host, port, timeout)

        with counter_lock:
            scanned += 1
            current = scanned
            open_count = len(results)

        if is_open:
            with print_lock:
                sys.stdout.write("\r" + " " * 75 + "\r")
                banner_str = f"  [{banner}]" if banner else ""
                print(f"  [+] {port_num:<6} {service:<12}{banner_str}")
                results.append((port_num, service, banner))
                show_progress(current, total_ports, len(results))
        else:
            with print_lock:
                show_progress(current, total_ports, open_count)

        queue.task_done()


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}")
        sys.exit(1)


def save_txt(filepath: str, host: str, ip: str, args):
    with open(filepath, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  Port Scanner — Nicolas-Costin Tanasache\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Target  : {host} ({ip})\n")
        f.write(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        if results:
            f.write(f"  {'PORT':<8} {'SERVICE':<12} BANNER / TITLE\n")
            f.write(f"  {'-' * 60}\n")
            for port, service, banner in sorted(results):
                b = banner if banner else "-"
                f.write(f"  {port:<8} {service:<12} {b}\n")


def save_json(filepath: str, host: str, ip: str, args):
    data = {
        "scan_metadata": {
            "target": host,
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "ports_scanned": total_ports
        },
        "open_ports": [
            {"port": p, "service": s, "banner_or_title": b}
            for p, s, b in sorted(results)
        ]
    }
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)


def save_csv(filepath: str):
    with open(filepath, "w", newline="", encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Service", "Banner_Title"])
        for p, s, b in sorted(results):
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
    print(f"  [*] Discovering live hosts (timeout: {args.timeout}s)...\n")

    live_hosts = []
    disc_lock = threading.Lock()

    def discover(ip):
        if ping_host(ip, args.timeout):
            with disc_lock:
                live_hosts.append(ip)
                print(f"  [+] Host UP: {ip}")

    disc_threads = []
    for ip in hosts:
        t = threading.Thread(target=discover, args=(ip,))
        t.daemon = True
        t.start()
        disc_threads.append(t)
        if len(disc_threads) >= args.threads:
            for dt in disc_threads:
                dt.join()
            disc_threads = []
    for dt in disc_threads:
        dt.join()

    if not live_hosts:
        print("\n  [!] No live hosts found.")
        return

    live_hosts.sort(key=lambda x: list(map(int, x.split("."))))
    print(f"\n  [*] {len(live_hosts)} host(s) alive — starting port scan...\n")

    all_results = {}

    for ip in live_hosts:
        global results, scanned, total_ports
        results = []
        scanned = 0
        total_ports = len(ports)

        print("=" * 60)
        print(f"  Scanning {ip}")
        print("=" * 60)

        queue = Queue()
        for p in ports:
            queue.put(p)

        threads_list = []
        for _ in range(min(args.threads, total_ports)):
            t = threading.Thread(target=worker, args=(ip, queue, args.timeout))
            t.daemon = True
            t.start()
            threads_list.append(t)
        for t in threads_list:
            t.join()

        print(f"\n\n  Open ports: {len(results)}")
        if results:
            print(f"  {'PORT':<8} {'SERVICE':<12} BANNER / TITLE")
            print(f"  {'-' * 50}")
            for port, service, banner in sorted(results):
                b = banner if banner else "-"
                print(f"  {port:<8} {service:<12} {b[:45]}")
        print()

        all_results[ip] = list(results)

    if args.json:
        data = {
            "scan_type": "network",
            "network": network,
            "timestamp": datetime.now().isoformat(),
            "live_hosts": len(live_hosts),
            "results": {
                ip: [{"port": p, "service": s, "banner": b}
                     for p, s, b in sorted(all_results[ip])]
                for ip in all_results
            }
        }
        with open(args.json, "w") as f:
            json.dump(data, f, indent=4)
        print(f"  [+] Network report saved: {args.json}")


def main():
    global total_ports

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

    if args.ports:
        try:
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
        t = threading.Thread(target=worker, args=(ip, queue, args.timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    duration = (datetime.now() - start_time).total_seconds()

    print("\n\n" + "=" * 60)
    print(f"  Scan complete in {duration:.2f}s")
    print(f"  Open ports found: {len(results)}")

    if results:
        print(f"\n  {'PORT':<8} {'SERVICE':<12} BANNER / TITLE")
        print(f"  {'-' * 60}")
        for port, service, banner in sorted(results):
            b = banner if banner else "-"
            print(f"  {port:<8} {service:<12} {b[:55]}")
    print("=" * 60)

    if args.output:
        save_txt(args.output, args.host, ip, args)
        print(f"  [+] Saved TXT  : {args.output}")
    if args.json:
        save_json(args.json, args.host, ip, args)
        print(f"  [+] Saved JSON : {args.json}")
    if args.csv:
        save_csv(args.csv)
        print(f"  [+] Saved CSV  : {args.csv}")

if __name__ == "__main__":
    main()