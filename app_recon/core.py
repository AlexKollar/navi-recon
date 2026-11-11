"""Navi Recon command core: parsing, scan/ping reporting, and the
--test self-test (loopback only — it never touches a network
beyond 127.0.0.1).

Grammar:
    recon                              this help
    recon scan <target> [options]      TCP connect scan + explainer
    recon ping <target> [options]      TCP reachability (not ICMP)
    recon --test                       self-test on loopback
    recon --help                       this help

Scan options:
    --ports 22,80,443   custom port list (max 1024)
    --top N             first N of the ranked list (default: top 44)
    --timeout <s>       per-port connect timeout (default 0.5)
    --i-own-this        assert ownership of an out-of-scope target
"""

import socket
import threading
import time

try:
    from . import scan as scanner
    from . import services
except ImportError:
    from app_recon import scan as scanner
    from app_recon import services

VERSION = "1.0.0"
USAGE = "usage: recon scan <target> [options] | recon ping <target> | recon --test"


def print_help():
    print("Navi Recon %s — scoped port scanning with a defender's "
          "explainer." % VERSION)
    print(USAGE)
    print("")
    print("  scan <target>       TCP connect scan of the top %d ports "
          "(or --ports / --top N);" % len(services.DEFAULT_PORTS))
    print("                      every open port gets its banner and a")
    print("                      hardening note. Connect-scan only — no")
    print("                      raw sockets, no SYN tricks.")
    print("  ping <target>       TCP reachability check (ports %s) — not"
          % "/".join(str(p) for p in scanner.PING_PORTS))
    print("                      ICMP ping; no raw sockets here either.")
    print("  --test              self-test on 127.0.0.1 — no lab needed.")
    print("")
    print("Scope: localhost, RFC1918, and link-local targets only. A")
    print("target that resolves to a public address is refused unless")
    print("--i-own-this asserts it is yours to scan.")


def print_scan(result):
    if result["allow_public"]:
        print(scanner.warning_text(result["target"]))
    header = "Navi Recon — scan of %s" % result["target"]
    if result["ip"] != result["target"]:
        header += " (%s)" % result["ip"]
    print(header)
    print("TCP connect scan: %d ports, %.2fs. Connect-scan only — "
          "a 'filtered' port may be dropped by a firewall, not proven "
          "closed." % (result["ports_tried"], result["duration"]))
    print("")
    opens = [r for r in result["results"] if r["state"] == "open"]
    closed = sum(1 for r in result["results"] if r["state"] == "closed")
    filtered = sum(1 for r in result["results"] if r["state"] == "filtered")
    if not opens:
        print("No open ports in the set I tried.")
    for r in opens:
        port = r["port"]
        print("%d/tcp  open  %s" % (port, services.service_name(port)))
        if port == 443:
            print("  banner: (none — TLS speaks second; a handshake "
                  "was not attempted)")
        elif r["banner"]:
            print("  banner: %s" % r["banner"])
        else:
            print("  banner: (the service stayed silent)")
        print("  " + services.explainer(port))
        print("")
    print("Done: %d open, %d closed, %d filtered of %d ports in %.2fs."
          % (len(opens), closed, filtered, result["ports_tried"],
             result["duration"]))


def print_ping(result):
    if result["allow_public"]:
        print(scanner.warning_text(result["target"]))
    print("Navi Recon — ping of %s (%s)"
          % (result["target"], result["ip"]))
    print("This is a TCP reachability check, not ICMP ping: no raw "
          "sockets, no privileges, just connect attempts.")
    if result["reachable"]:
        print("REACHABLE — %s answered a TCP connect on port %d in "
              "%.0f ms." % (result["ip"], result["port"], result["ms"]))
    else:
        tried = ", ".join(str(p) for p, _, _ in result["attempts"])
        print("No answer on the probe ports (%s). The host may be "
              "down, firewalled, or simply not listening on any of "
              "them — a TCP check can't tell those apart, and I "
              "won't pretend it can." % tried)


def _parse_options(rest):
    options = {"ports": None, "top": None, "timeout": 0.5,
               "i-own-this": False}
    target = None
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--ports":
            i += 1
            if i >= len(rest):
                raise ValueError("--ports needs a list, e.g. --ports 22,80,443")
            options["ports"] = rest[i]
        elif tok == "--top":
            i += 1
            if i >= len(rest):
                raise ValueError("--top needs a count, e.g. --top 100")
            options["top"] = rest[i]
        elif tok == "--timeout":
            i += 1
            if i >= len(rest):
                raise ValueError("--timeout needs seconds, e.g. --timeout 0.5")
            try:
                options["timeout"] = float(rest[i])
            except ValueError:
                raise ValueError("--timeout needs a number of seconds.")
            if not 0.05 <= options["timeout"] <= 5.0:
                raise ValueError("--timeout must be between 0.05 and 5 seconds.")
        elif tok == "--i-own-this":
            options["i-own-this"] = True
        elif tok.startswith("--"):
            raise ValueError("unknown option %r — run recon with no "
                             "arguments for the help." % tok)
        elif target is None:
            target = tok
        else:
            raise ValueError("one target at a time — %r is extra." % tok)
        i += 1
    return target, options


def _run(argv):
    if not argv:
        print_help()
        return 0
    head = argv[0]
    if head in ("--help", "-h", "help"):
        print_help()
        return 0
    if head == "--test":
        return self_test()
    if head == "scan":
        target, options = _parse_options(argv[1:])
        if target is None:
            print("scan needs a target: recon scan <target> [options]")
            return 2
        ports = scanner.ports_for(options)
        result = scanner.scan(target, ports, options["timeout"],
                              options["i-own-this"])
        print_scan(result)
        return 0
    if head == "ping":
        target, options = _parse_options(argv[1:])
        if target is None:
            print("ping needs a target: recon ping <target>")
            return 2
        result = scanner.ping(target, options["timeout"],
                              options["i-own-this"])
        print_ping(result)
        return 0
    print("unknown command %r — run recon with no arguments for the "
          "help." % head)
    return 2


def run_command(argv):
    """Entry for root.py. Prints everything; a refusal is a sentence,
    never a traceback."""
    try:
        return _run(list(argv))
    except scanner.Refused as exc:
        print(str(exc))
        return 0
    except ValueError as exc:
        print("error: " + str(exc))
        return 1
    except Exception as exc:  # a chip in a sandbox stays polite
        print("error: " + str(exc))
        return 1


# ---------------- self-test (loopback only) ----------------

class _Listener:
    """Throwaway listener on 127.0.0.1, ephemeral port. Optionally
    speaks a banner on connect."""

    def __init__(self, banner=None, hold=0.0):
        self.banner = banner
        self.hold = hold
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                if self.banner:
                    conn.sendall(self.banner)
                if self.hold:
                    time.sleep(self.hold)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=1.0)


def _closed_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def self_test():
    checks = []

    def check(label, fn):
        try:
            ok = bool(fn())
            detail = ""
        except Exception as exc:
            ok = False
            detail = ": " + str(exc)
        checks.append((label, ok, detail))

    banner_listener = _Listener(banner=b"SSH-2.0-OpenSSH_8.9\r\n").start()
    silent_listener = _Listener(hold=0.4).start()
    closed = _closed_port()
    try:
        ports = [banner_listener.port, silent_listener.port, closed]
        result = scanner.scan("127.0.0.1", ports, timeout=1.0)
        by_port = {r["port"]: r for r in result["results"]}

        check("scan classifies banner port open",
              lambda: by_port[banner_listener.port]["state"] == "open")
        check("banner captured and sanitized",
              lambda: by_port[banner_listener.port]["banner"]
              == "SSH-2.0-OpenSSH_8.9")
        check("silent port still open, banner None",
              lambda: by_port[silent_listener.port]["state"] == "open"
              and by_port[silent_listener.port]["banner"] is None)
        check("closed port classified closed",
              lambda: by_port[closed]["state"] == "closed")
        check("every open port carries an explainer",
              lambda: all(services.explainer(r["port"])
                          for r in result["results"]
                          if r["state"] == "open"))
        def _ping_finds_listener():
            real = scanner.PING_PORTS
            scanner.PING_PORTS = (banner_listener.port,)
            try:
                out = scanner.ping("127.0.0.1", timeout=1.0)
                return (out["reachable"] is True
                        and out["port"] == banner_listener.port)
            finally:
                scanner.PING_PORTS = real

        check("ping finds a staged listener via its probe set",
              _ping_finds_listener)
        check("localhost resolves inside the guardrail",
              lambda: scanner.resolve_and_check("localhost")[0]
              in ("127.0.0.1", "::1"))

        def _refusal_before_connect():
            calls = []
            real_connect = socket.socket.connect
            real_connect_ex = socket.socket.connect_ex

            def tripwire(self, *a, **k):
                calls.append(a)
                raise AssertionError("a connection was attempted")

            socket.socket.connect = tripwire
            socket.socket.connect_ex = tripwire
            try:
                try:
                    scanner.scan("203.0.113.10", [22], timeout=0.2)
                except scanner.Refused as exc:
                    return (str(exc).startswith("Recon only scans")
                            and "203.0.113.10" in str(exc)
                            and not calls)
                return False
            finally:
                socket.socket.connect = real_connect
                socket.socket.connect_ex = real_connect_ex

        check("guardrail refuses a public IP before any connect",
              _refusal_before_connect)
        check("port parser accepts a custom list",
              lambda: scanner.parse_ports("22, 80,443") == [22, 80, 443])
        check("port parser enforces the 1024 cap",
              lambda: _raises_value_error(
                  lambda: scanner.parse_ports(
                      ",".join(str(p) for p in range(1, 2000)))))
        check("default set is the curated top 44",
              lambda: scanner.ports_for({}) == services.DEFAULT_PORTS
              and len(services.DEFAULT_PORTS) == 44)
        check("--top 100 draws on the ranked list",
              lambda: len(scanner.ports_for({"top": "100"})) == 100)
    finally:
        banner_listener.close()
        silent_listener.close()

    passed = 0
    for label, ok, detail in checks:
        print("%s %s%s" % ("PASS" if ok else "FAIL", label, detail))
        if ok:
            passed += 1
    print("self-test: %d/%d passed" % (passed, len(checks)))
    return 0 if passed == len(checks) else 1


def _raises_value_error(fn):
    try:
        fn()
    except ValueError:
        return True
    return False
