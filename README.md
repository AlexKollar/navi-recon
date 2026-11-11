# Navi Recon

Port scanning and service fingerprinting that rides inside a single
Apex chip — built for a cybersecurity student's lab work. It does a
TCP connect scan, reads the banner, and attaches **a defender's
explainer to every open port**: what the service is, why being
exposed matters, and what hardening looks like. The scan is the
easy part; the explanation is the chip.

This is a fresh build in the modern `navi-chip/1` format — not a
port of the legacy SaintsSec `navi-nmap`.

## Using it

In Apex chat, or anywhere the chip runs:

```
recon                              help
recon scan <target>                scan the curated top 44 ports
recon scan <target> --ports 22,80,443
recon scan <target> --top 100      first 100 of the ranked list
recon scan <target> --timeout 1    slower, kinder connects
recon ping <target>                TCP reachability (not ICMP)
recon --test                       self-test on loopback
```

Worked example (against your own lab box):

```
$ recon scan 192.168.1.20 --ports 22,80
Navi Recon — scan of 192.168.1.20
TCP connect scan: 2 ports, 0.03s. ...

22/tcp  open  ssh
  banner: SSH-2.0-OpenSSH_8.9
  SSH is the remote shell — encrypted, key-based, ...

80/tcp  open  http
  banner: HTTP/1.0 200 OK | Server: Apache/2.4
  HTTP serves a website in the clear. ...

Done: 2 open, 0 closed, 0 filtered of 2 ports in 0.03s.
```

## The guardrail — read this first

Navi's posture is gray-hat-leaning-white, and this chip enforces
it in code, not in a EULA:

- Targets must be **localhost, an RFC1918 private address, a
  link-local address, or a hostname that resolves ONLY to such
  addresses**. Resolution happens once, before anything connects.
- A target that resolves to any public address is **refused in
  plain words**, before a single connection is attempted:

  > Recon only scans your own machines and lab ranges —
  > `example.com` resolves to a public address, so I won't touch it.

- The scope test is explicit network membership. It deliberately
  does **not** use `ipaddress.is_private`, because that flag also
  counts the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24) and other special registries as "private" — and
  a documentation address is nobody's lab box. CGNAT space
  (100.64.0.0/10) is likewise **not** treated as yours by default.
- The one override is `--i-own-this`: an explicit assertion that
  the target is yours or you are authorized to scan it. It prints
  a loud warning line at the top of the output, every time. If the
  assertion isn't true, don't pass the flag — an uninvited scan is
  how you get expelled, fired, or charged.

## What the scan is — and isn't

- **Connect-scan only.** Full TCP connects, standard library
  sockets. No raw sockets, no SYN/half-open tricks, no privileges
  needed — and no stealth either: a connect scan is visible in the
  target's logs, which is the honest way to scan your own lab.
- **Banners are read passively** — the services that speak first
  (SSH, FTP, SMTP, MySQL, ...) get heard, up to 256 bytes,
  sanitized to one printable line.
- **One documented exception:** on likely-HTTP ports (80, 8000,
  8008, 8080, 8081, 8888, 9000, 9090, 5000, 3128), if the service
  stays silent, the chip sends a bare `HEAD / HTTP/1.0` probe and
  reads the status line and `Server:` header. Nothing beyond a
  connect is ever sent to any other port.
- **Port 443 gets no banner.** TLS speaks second — the server
  waits for a ClientHello — and this chip does not perform a TLS
  handshake in v1. HTTPS reports "no banner, by design" and the
  explainer points you at the certificate instead.
- **"Filtered" means timed out.** A firewall may be dropping the
  packets; a connect scan can't prove a filtered port closed, and
  the output says so.
- **Ping is TCP reachability, not ICMP ping.** It connects to
  443, 80, 22, and 7 in order and reports the first that answers.
  No answer means down, firewalled, *or* just not listening on
  those ports — the output says it can't tell those apart.
- Caps: **1024 ports per run**; per-port timeout defaults to
  **0.5s** (adjustable 0.05–5s). The ranked list holds 132 ports;
  `--top N` takes the first N.

## The explainer

`app_recon/services.py` carries 100+ specific briefs — what the
service is, the risk of it being exposed, the hardening move — plus
a generic fallback for unlisted ports: find the owning process
(`ss -tlnp`), and if you can't name the listener, *that* is the
finding. Faces are forge-time: the chip's declared radar `icon`
outranks its built-in glyph on the cartridge picture.

## Standard library only

`socket`, `ipaddress`, `concurrent.futures` — nothing to install,
nothing to break in a locked-down lab. `chip-requirements.txt`
says so in so many words.

## Install it in Apex

1. Open the **Chips** tab, then **Navi User Repo (NUR)**.
2. **Search NUR** — every public repo tagged `navi-chips` is listed.
3. **Install** — Apex downloads every Python file in the repo at
   the latest release, keeping folder paths, and forges them into
   a chip: `root.py` is the entry, the `app_recon/` package rides
   beside it.

## Files

- `root.py` — the chip entry (`run(args)`); small on purpose.
- `app_recon/core.py` — argument parsing, reporting, `--test`.
- `app_recon/scan.py` — the guardrail, resolution, connect scan,
  banner reading, TCP ping.
- `app_recon/services.py` — the ranked port list, service names,
  and the defender's explainer.
- `navi-chip.json` — the `navi-chip/1` manifest.
- `navi-recon.png` — the forged cartridge (once forged).

## Publishing an update

Edit the code, bump `version` in `navi-chip.json`, push, and
publish a new release — a newer release tag is what offers
everyone who installed the chip an update. Keep the `navi-chips`
topic on the repo; that is how Apex finds it.

## License

MIT — see `LICENSE`. Copyright (c) SaintsSec.
