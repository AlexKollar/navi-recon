"""Navi Recon — the scanner: target guardrails, the TCP connect
scan, banner reading, and the TCP reachability probe.

THE GUARDRAIL (Navi's posture is gray-hat-leaning-white): a target
must be localhost, an RFC1918 private address, a link-local
address, or a hostname that resolves ONLY to such addresses.
Anything else is refused in plain words BEFORE any connection is
attempted, unless the operator passes --i-own-this — an explicit
assertion of ownership — which prints a loud warning line in the
output. The check is explicit network membership, NOT
``ipaddress.is_private``: that flag also counts the documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and other
special registries as "private", and a documentation address is
nobody's lab box.

THE SCAN is connect-scan only: full TCP connects, no raw sockets,
no SYN tricks, no privileges needed. Banners are read passively —
the services that speak first get heard. The one exception: on
likely-HTTP ports, if the service stays silent, a bare
``HEAD / HTTP/1.0`` probe is sent and the status line is read.
Nothing beyond a connect is ever sent to any other port. Port 443
gets no probe and no handshake: TLS speaks second, so https
reports no banner, by design.
"""

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor

try:
    from . import services
except ImportError:
    from app_recon import services

ALLOWED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),          # loopback v6
    ipaddress.ip_network("fc00::/7"),         # unique-local v6
    ipaddress.ip_network("fe80::/10"),        # link-local v6
]

# Ports where a silent service is probably HTTP and gets the one
# documented probe. 443 is deliberately absent (TLS).
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 5000, 3128}

MAX_PORTS = 1024
BANNER_BYTES = 256
PING_PORTS = (443, 80, 22, 7)


class Refused(Exception):
    """The guardrail said no. The message is the user-facing text."""


def refusal_text(target):
    return ("Recon only scans your own machines and lab ranges — %s "
            "resolves to a public address, so I won't touch it." % target)


def warning_text(target):
    return ("!! --i-own-this: scanning %s on YOUR assertion that it is "
            "yours or you are authorized to scan it. If that isn't true, "
            "stop now — an uninvited scan is how you get expelled, "
            "fired, or charged. !!" % target)


def _allowed(ip):
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in ALLOWED_NETS
               if net.version == addr.version)


def resolve_and_check(target, allow_public=False):
    """Resolve once, apply the guardrail, return (connect_ip, [all_ips]).

    Raises Refused for an out-of-scope target (before anything
    connects), ValueError for a name that won't resolve.
    """
    literal = None
    try:
        literal = ipaddress.ip_address(target)
    except ValueError:
        literal = None
    if literal is not None:
        ips = [str(literal)]
    else:
        try:
            infos = socket.getaddrinfo(target, None, 0, socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError("couldn't resolve %r — check the name, or "
                             "use an IP address." % target)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        if not ips:
            raise ValueError("couldn't resolve %r — it answered with "
                             "no addresses." % target)
    if not allow_public and any(not _allowed(ip) for ip in ips):
        raise Refused(refusal_text(target))
    # Prefer the first IPv4 address for the actual connection.
    connect_ip = next((ip for ip in ips if ":" not in ip), ips[0])
    return connect_ip, ips


def sanitize_banner(raw):
    """Banner bytes -> one printable line, or None."""
    if not raw:
        return None
    text = raw[:BANNER_BYTES].decode("latin-1")
    cleaned = "".join(c if (c.isprintable() or c == " ") else "."
                      for c in text)
    cleaned = " ".join(cleaned.split()).strip(" .")
    if not cleaned:
        return None
    return cleaned[:120]


def _read_banner(sock, port, timeout):
    # Pass 1: listen. SSH, FTP, SMTP, MySQL and friends speak first.
    sock.settimeout(min(max(timeout, 0.2), 0.6))
    try:
        data = sock.recv(BANNER_BYTES)
    except (socket.timeout, TimeoutError, OSError):
        data = b""
    if data:
        return sanitize_banner(data)
    # Pass 2 (HTTP ports only): the documented probe.
    if port in HTTP_PORTS:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(BANNER_BYTES)
        except (socket.timeout, TimeoutError, OSError):
            data = b""
        if data:
            line = data.split(b"\r\n", 1)[0]
            server = b""
            for part in data.split(b"\r\n"):
                if part.lower().startswith(b"server:"):
                    server = part.split(b":", 1)[1].strip()
                    break
            probe = line + (b" | Server: " + server if server else b"")
            return sanitize_banner(probe)
    return None


def probe_port(ip, port, timeout):
    """One port: connect, classify, banner if open."""
    sock = socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6,
                         socket.SOCK_STREAM)
    started = time.monotonic()
    try:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except ConnectionRefusedError:
            return {"port": port, "state": "closed", "banner": None,
                    "ms": 0.0}
        except (socket.timeout, TimeoutError):
            return {"port": port, "state": "filtered", "banner": None,
                    "ms": (time.monotonic() - started) * 1000.0}
        except OSError:
            return {"port": port, "state": "filtered", "banner": None,
                    "ms": (time.monotonic() - started) * 1000.0}
        ms = (time.monotonic() - started) * 1000.0
        banner = _read_banner(sock, port, timeout)
        return {"port": port, "state": "open", "banner": banner, "ms": ms}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def scan(target, ports, timeout=0.5, allow_public=False):
    """Full scan. Returns a structured result; raises Refused /
    ValueError from the guardrail before connecting anywhere."""
    connect_ip, all_ips = resolve_and_check(target, allow_public)
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=48) as pool:
        results = list(pool.map(
            lambda p: probe_port(connect_ip, p, timeout), ports))
    duration = time.monotonic() - started
    results.sort(key=lambda r: r["port"])
    return {
        "target": target,
        "ip": connect_ip,
        "all_ips": all_ips,
        "ports_tried": len(ports),
        "results": results,
        "duration": duration,
        "allow_public": allow_public,
    }


def ping(target, timeout=0.5, allow_public=False):
    """TCP reachability — NOT ICMP ping. Probes PING_PORTS and
    reports the first that answers. Same guardrail as scan."""
    connect_ip, all_ips = resolve_and_check(target, allow_public)
    attempts = []
    for port in PING_PORTS:
        started = time.monotonic()
        sock = socket.socket(
            socket.AF_INET if ":" not in connect_ip else socket.AF_INET6,
            socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            try:
                sock.connect((connect_ip, port))
                ms = (time.monotonic() - started) * 1000.0
                attempts.append((port, True, ms))
                return {"target": target, "ip": connect_ip,
                        "all_ips": all_ips, "reachable": True,
                        "port": port, "ms": ms, "attempts": attempts,
                        "allow_public": allow_public}
            except OSError:
                attempts.append((port, False, 0.0))
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return {"target": target, "ip": connect_ip, "all_ips": all_ips,
            "reachable": False, "port": None, "ms": 0.0,
            "attempts": attempts, "allow_public": allow_public}


def parse_ports(text):
    """'22,80,443' -> [22, 80, 443], validated. Raises ValueError."""
    ports = []
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
        except ValueError:
            raise ValueError("%r is not a port number." % part)
        if not 1 <= port <= 65535:
            raise ValueError("port %d is out of range (1-65535)." % port)
        if port not in ports:
            ports.append(port)
    if not ports:
        raise ValueError("no ports given.")
    if len(ports) > MAX_PORTS:
        raise ValueError("that's %d ports — the cap is %d per run. "
                         "Split the scan up." % (len(ports), MAX_PORTS))
    return ports


def ports_for(options):
    """Resolve --ports / --top / default into the port list."""
    if options.get("ports"):
        return parse_ports(options["ports"])
    top = options.get("top")
    if top is not None:
        try:
            top = int(top)
        except (TypeError, ValueError):
            raise ValueError("--top needs a count, e.g. --top 100.")
        if top < 1:
            raise ValueError("--top needs a count of at least 1.")
        if top > len(services.RANKED):
            raise ValueError("the ranked list holds %d ports — --top %d "
                             "asks for more than I know. Use --ports for "
                             "a custom set." % (len(services.RANKED), top))
        return [p for p, _ in services.RANKED[:top]]
    return list(services.DEFAULT_PORTS)
