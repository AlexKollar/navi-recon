"""Navi Recon — port data: the ranked top-ports list, service
names, and the defender's explainer for every open port.

The explainer is the point of the chip: each open port gets one or
two lines saying what the service is, why being exposed matters,
and what hardening looks like. Ports with no specific entry get the
generic fallback — an unidentified listener is itself a finding.

Port ordering follows the usual "most often open" ranking; the
default scan runs the first 44 (DEFAULT_PORTS). ``--top N`` takes
the first N of RANKED (there are more than 130).
"""

# (port, service name), most-often-open first. Names are the field
# guide names a student will meet (IANA where the IANA name is the
# one in use, the common name where it isn't).
RANKED = [
    (22, "ssh"), (80, "http"), (443, "https"), (21, "ftp"),
    (25, "smtp"), (3389, "ms-wbt-server"), (110, "pop3"),
    (445, "microsoft-ds"), (139, "netbios-ssn"), (143, "imap"),
    (53, "domain"), (3306, "mysql"), (8080, "http-proxy"),
    (1723, "pptp"), (111, "rpcbind"), (135, "msrpc"),
    (5900, "vnc"), (993, "imaps"), (995, "pop3s"), (23, "telnet"),
    (8443, "https-alt"), (587, "submission"), (465, "smtps"),
    (631, "ipp"), (873, "rsync"), (5432, "postgresql"),
    (6379, "redis"), (5060, "sip"), (5061, "sip-tls"),
    (1433, "ms-sql-s"), (1521, "oracle"), (2049, "nfs"),
    (389, "ldap"), (636, "ldaps"), (88, "kerberos"),
    (514, "shell"), (515, "printer"), (179, "bgp"),
    (1080, "socks"), (3128, "squid-http"), (8000, "http-alt"),
    (8008, "http-alt"), (8009, "ajp13"), (8081, "http-alt"),
    (8888, "http-alt"), (9000, "cslistener"), (9090, "zeus-admin"),
    (9200, "elasticsearch"), (27017, "mongodb"), (11211, "memcached"),
    (5985, "wsman"), (5986, "wsmans"), (6000, "x11"),
    (6667, "irc"), (1194, "openvpn"), (548, "afp"), (554, "rtsp"),
    (990, "ftps"), (1720, "h323"), (2082, "cpanel"),
    (2083, "cpanel-ssl"), (2086, "whm"), (2087, "whm-ssl"),
    (2181, "zookeeper"), (2222, "ssh-alt"), (2375, "docker"),
    (2376, "docker-ssl"), (2483, "oracle-ssl"), (3260, "iscsi"),
    (3690, "svn"), (4369, "epmd"), (4444, "krb524"),
    (5000, "http-alt"), (5601, "kibana"), (5672, "amqp"),
    (5901, "vnc-1"), (6443, "kube-apiserver"), (7001, "weblogic"),
    (8086, "influxdb"), (8088, "radan-http"), (8090, "opsmessaging"),
    (8161, "activemq"), (8500, "consul"), (8834, "nessus"),
    (9001, "tor-orport"), (9042, "cassandra"), (9100, "jetdirect"),
    (9300, "elasticsearch-cl"), (9418, "git"), (9999, "abyss"),
    (10000, "webmin"), (15672, "rabbitmq-mgmt"), (27018, "mongodb-shard"),
    (50070, "hadoop-namenode"), (113, "ident"), (119, "nntp"),
    (427, "svrloc"), (79, "finger"), (49, "tacacs"),
    (102, "iso-tsap"), (26, "smtp-alt"), (37, "time"),
    (20, "ftp-data"), (69, "tftp"), (161, "snmp"),
    (137, "netbios-ns"), (138, "netbios-dgm"), (123, "ntp"),
    (67, "bootps"), (101, "hostname"), (512, "exec"),
    (513, "login"), (593, "http-rpc-epmap"), (623, "asf-rmcp"),
    (749, "kerberos-adm"), (901, "samba-swat"), (992, "telnets"),
    (989, "ftps-data"), (3659, "apple-sasl"), (4045, "lockd"),
    (6001, "x11:1"), (7070, "realserver"), (8002, "teradataordbms"),
    (8010, "xmpp-server"), (8333, "bitcoin"), (8530, "wsus"),
    (8531, "wsus-ssl"), (9101, "bacula-dir"), (9102, "bacula-fd"),
    (9103, "bacula-sd"), (10080, "amanda"), (31337, "back-orifice"),
]

SERVICE = dict(RANKED)
DEFAULT_PORTS = [p for p, _ in RANKED[:44]]
TOP_N = len(RANKED)

EXPLAIN = {
    21: "FTP moves files in the clear — credentials and data cross the wire readable. "
        "On a lab box it's a classic foot-in-the-door; in production, FTPS or SFTP, and never anonymous write.",
    22: "SSH is the remote shell — encrypted, key-based, the way you administer a box. "
        "Harden it: key-only auth, no root login, no password auth on a public face, and fail2ban or a nonstandard port won't save a weak key.",
    23: "Telnet is an unencrypted remote shell — everything, including the password, in cleartext. "
        "Treat an open 23 as a finding on its own: it should be SSH or nothing.",
    25: "SMTP is mail relay. Open here it usually means a mail server (or a relay you didn't mean to run) — "
        "check it's not an open relay, and remember mail auth traffic can leak credentials in the clear.",
    53: "DNS answers name lookups. An open resolver that answers strangers can be abused for amplification "
        "and cache poisoning — a lab resolver should answer only its own network.",
    80: "HTTP serves a website in the clear. Read the banner and the Server header for what's behind it — "
        "an unpatched web app on 80 is the most common lab foothold there is.",
    110: "POP3 fetches mail, credentials in the clear unless STARTTLS is enforced. "
        "It's the older sibling of 995 — same job, weaker defaults.",
    111: "RPC portmapper advertises which RPC services a Unix host runs (NFS, NIS, ...). "
        "It's an enumeration goldmine: an attacker asks it what else is here. Firewall it off the network.",
    135: "MSRPC — Windows' remote procedure calls, the doorway DCOM and friends use. "
        "Historically worm food (Blaster and friends); on a lab Windows box it's expected, on a server it should never face strangers.",
    139: "NetBIOS session service — legacy Windows file/printer sharing. "
        "Old, chatty, and a classic enumeration target; modern networks use 445 alone and still shouldn't expose it.",
    143: "IMAP fetches mail, cleartext unless STARTTLS. Like POP3, the question is always: "
        "is the password crossing the wire encrypted, and is the mailbox behind it patched?",
    443: "HTTPS — the encrypted web. A TLS handshake is needed before the server says anything, "
        "so no banner is shown here by design. Check the certificate (name, expiry) — a lab cert that says the wrong name is its own lesson.",
    445: "SMB — Windows file sharing and a lot more (auth, named pipes, lateral movement). "
        "EternalBlue made this port famous; an exposed 445 with a weak share is a foothold, and SMB signing should be required, not optional.",
    465: "SMTPS — SMTP wrapped in TLS from the first byte. Safer than 25 in transit; "
        "the question is still whether the mail server relays for strangers.",
    514: "Remote shell (rsh/rexec family) — trust-based, barely-authenticated remote execution from another era. "
        "Anything on 514 in a modern lab is a deliberate vulnerability: replace with SSH.",
    515: "Line printer daemon — network printing. Old and rarely patched; a printer on the network is a computer "
        "that happens to print, so treat it like one.",
    587: "SMTP submission — where mail clients hand mail to the server, authenticated. "
        "Watch for weak auth and credential stuffing; it's the port a phisher's botnet knocks on.",
    631: "IPP — network printing (CUPS). Printers are networked computers with old firmware; "
        "an open 631 that accepts jobs from anywhere is a free document shredder and a pivot point.",
    636: "LDAPS — LDAP over TLS, the directory service (users, groups, machines). "
        "Anonymous binds and weak passwords here hand an attacker the org chart; require TLS and least-privilege binds.",
    873: "rsync — file sync, often anonymous and unauthenticated by design. "
        "An open rsync module can leak whole directories or let an attacker write files; lock modules to hosts and require auth.",
    88: "Kerberos — the ticket service behind Active Directory login. It's the crown jewels' front door: "
        "a weak service account password turns into a golden ticket. Harden with strong, long service passwords.",
    179: "BGP — routers exchanging routes. You almost never want a BGP speaker answering strangers; "
        "an exposed one can be tricked into misrouting traffic.",
    389: "LDAP — the directory service, unencrypted. Directory data (users, groups, machines) in cleartext is "
        "recon served on a plate; require TLS (636) and authenticated binds.",
    1080: "SOCKS proxy — a generic traffic relay. An open SOCKS proxy is a free anonymizer for anyone who finds it, "
        "and a classic pivot point once a box is owned.",
    1433: "Microsoft SQL Server. A database that answers the network — check for sa with a weak password, "
        "and remember SQL Server has historically been a remote-code-execution vector (xp_cmdshell).",
    1521: "Oracle Database listener. Same story as any DB on the wire: default/weak credentials are the find; "
        "the listener should never be reachable from outside its own segment.",
    2049: "NFS — network file sharing. Export lists are the thing to read: an export with no_root_squash to the "
        "world means anyone can write files as root on the share.",
    3128: "Squid proxy — HTTP proxy. An open proxy relays other people's traffic (and abuse) through your box; "
        "lock it to your own networks.",
    3306: "MySQL/MariaDB. A database on the wire: the finding is usually a root account with a weak or empty password, "
        "or a database that accepts connections from everywhere.",
    3389: "RDP — the Windows remote desktop. Encrypted login, but a prime brute-force target and the delivery "
        "vector for ransomware; require NLA, strong passwords, and ideally a VPN or gateway in front of it.",
    5432: "PostgreSQL. A database on the wire — same discipline as MySQL: strong credentials, listen only on "
        "the addresses that need it, and never the internet.",
    5900: "VNC — remote desktop, often with a weak or single shared password and no lockout. "
        "An open VNC is frequently a straight line to the desktop; tunnel it through SSH or a VPN.",
    5985: "WinRM HTTP — Windows Remote Management, PowerShell remoting over HTTP. "
        "It's remote administration: if you can reach it, so can a password spray. Require HTTPS (5986) and strong auth.",
    5986: "WinRM HTTPS — PowerShell remoting over TLS. Same power as 5985, encrypted; "
        "still a remote-admin door, so treat it like one.",
    6000: "X11 — the Unix display server, from when graphics crossed the network. "
        "An open X11 lets anyone watch keystrokes and inject input; it has no business on a modern network.",
    6379: "Redis — an in-memory store that historically shipped with NO authentication at all. "
        "An open 6379 is often full read/write to the data; require AUTH, bind to localhost, and never expose it.",
    6667: "IRC — chat. Mostly a curiosity now; an open IRC port on a lab box is usually a service someone forgot, "
        "or a bot's command-and-control channel — either way, ask why it's there.",
    8080: "HTTP on the alternate port — often a proxy, a dev server, or an admin console (Tomcat, Jenkins, ...). "
        "Check what answers: admin panels on 8080 with default credentials are a lab classic.",
    8088: "HTTP-alt, often a service console (Hadoop, Radan). Read the banner — consoles on alternate ports "
        "are where default passwords hide.",
    8443: "HTTPS on the alternate port — usually an admin console or appliance web UI over TLS. "
        "Same rule as 8080: identify the console and check its credentials.",
    9000: "Often a web admin or debug console (PHP-FPM, SonarQube, various). "
        "Identify what answers and check whether it's an admin door with a default password.",
    9090: "HTTP-alt — web admin consoles and proxies live here. Identify the service from the banner "
        "and check its auth.",
    9200: "Elasticsearch HTTP API — a search engine that historically shipped with no authentication. "
        "An open 9200 can expose every indexed document and, in old versions, allow script execution.",
    993: "IMAPS — IMAP over TLS. Mail fetch, encrypted; the mailbox behind it still needs a strong password "
        "and a patched server.",
    995: "POP3S — POP3 over TLS. Same job as 110, encrypted in transit; check the mailbox credentials.",
    11211: "Memcached — a memory cache with NO authentication by design. An open 11211 leaks cached data and "
        "can be abused for UDP amplification; it should never face a network it doesn't trust.",
    1194: "OpenVPN — a VPN endpoint. A VPN that answers strangers is expected; the finding is in the config — "
        "weak shared keys or no certificate auth.",
    1723: "PPTP — an old VPN protocol with broken cryptography. Treat an open 1723 as a finding: "
        "replace with OpenVPN or WireGuard.",
    2375: "Docker's remote API, unauthenticated — anyone who can reach it can start containers, mount the host "
        "filesystem, and own the machine. Never expose 2375; 2376 (TLS) is the minimum, and even that behind a firewall.",
    2376: "Docker's remote API over TLS. Better than 2375, but still remote root if the credentials leak — "
        "restrict who can reach it.",
    27017: "MongoDB — a database that shipped for years with no authentication enabled by default. "
        "An open 27017 with data in it is the classic cloud leak; require auth and bind to localhost.",
    5000: "Often a dev server, a Flask app, or a service console. Identify what answers — dev servers on 5000 "
        "with debug mode on are remote code execution waiting to happen.",
    8000: "HTTP-alt — dev servers and service consoles. Same rule as 8080: read the banner, check the auth.",
    8009: "AJP — Tomcat's backend connector. An exposed AJP (Ghostcat and friends) can read webapp files and, "
        "in bad versions, execute code; it should only ever listen on localhost.",
    8161: "ActiveMQ web console. A message broker's admin UI on the wire — default credentials are the find.",
    8834: "Nessus — a vulnerability scanner's own web UI. Ironic and real: a scanner left open is itself "
        "a target; protect it like any admin console.",
    10000: "Webmin — server admin over the web. A full root-level admin UI; an open 10000 with a weak password "
        "is the whole machine.",
    15672: "RabbitMQ management UI. A message broker's admin console — default guest/guest credentials "
        "are the classic finding.",
    50070: "Hadoop NameNode web UI — cluster administration over HTTP. An open Hadoop console is "
        "cluster-wide access; restrict it to operators.",
    6443: "Kubernetes API server. The cluster's control plane: whoever can talk to 6443 with a valid token "
        "can run anything in the cluster. Never expose it beyond its operators.",
    9042: "Cassandra — a distributed database's native protocol. Same discipline as any DB on the wire: "
        "auth on, bind tight, never public.",
    9100: "JetDirect — network printing (HP). A printer on the network is a computer that prints; "
        "an open 9100 accepts raw print jobs from anyone.",
    9418: "Git daemon — serves repositories anonymously. Check what's shared: an open git:// can leak "
        "source code nobody meant to publish.",
    9999: "Unassigned — a service someone chose, or a backdoor's favourite hiding place. "
        "Identify the owning process first; an unexplained 9999 is a finding on its own.",
    7: "Echo — the oldest service on the list, it repeats what you send. Mostly a curiosity; "
        "an open echo port on a modern box is usually a honeypot or a forgotten default.",
    20: "FTP data channel — the companion of port 21. Only meaningful next to an FTP server; "
        "see the 21 explainer.",
    69: "TFTP — trivial file transfer, no authentication at all, over UDP. "
        "Used for booting devices; an open TFTP can leak config files and firmware.",
    161: "SNMP — device management, often with the default community string 'public'. "
        "A read of SNMP is a full inventory of the device; write access is remote config. Change the community strings.",
    123: "NTP — time sync, over UDP. An open NTP can be abused for amplification attacks; "
        "restrict it to clients that need it.",
    137: "NetBIOS name service — legacy Windows name resolution. Chatty and enumerable; "
        "modern networks don't need it facing anything.",
    138: "NetBIOS datagram service — legacy Windows, same story as 137: enumeration fuel.",
    67: "DHCP — hands out addresses, over UDP. A rogue DHCP server on a lab network is a classic "
        "man-in-the-middle setup; the real one should be the only one answering.",
    113: "Ident — answers 'who owns this connection?' Mostly obsolete; an open ident leaks usernames "
        "to anyone who asks.",
    119: "NNTP — Usenet news. A curiosity in a modern lab; an open 119 is usually a service someone forgot.",
    427: "Service Location Protocol — devices advertising themselves. Useful for enumeration; "
        "restrict it to its own segment.",
    49: "TACACS+ — network device authentication. The keys to the routers; an open TACACS+ with a weak "
        "shared secret is the keys to the kingdom.",
    79: "Finger — tells anyone who asks which users are logged in. A gift to an attacker doing recon; "
        "it should be off.",
    104: "DICOM — medical imaging. A hospital-adjacent service; an open DICOM port can leak patient images — "
        "treat it as sensitive data, not a curiosity.",
    548: "Apple Filing Protocol — macOS file sharing. Same discipline as SMB: strong credentials, "
        "local segment only.",
    554: "RTSP — streaming video (cameras, media servers). An open RTSP can stream a camera feed to anyone; "
        "check the auth and the segment.",
    990: "FTPS — FTP over TLS. Better than 21 in transit; still FTP's trust model, so check the auth.",
    1720: "H.323 — video conferencing call setup. An open H.323 can be a free conference bridge; "
        "restrict it to its own segment.",
    2082: "cPanel — web hosting admin. A hosting panel on the wire: default/weak credentials are the find.",
    2083: "cPanel over TLS — same panel, encrypted. Still an admin door; check the credentials.",
    2086: "WHM — web host manager, the admin behind cPanel. Root-level hosting admin; "
        "protect it like one.",
    2087: "WHM over TLS — same as 2086, encrypted. Same discipline.",
    2181: "ZooKeeper — coordination for distributed systems. An open ZooKeeper lets anyone read and write "
        "the cluster's coordination data; restrict it to its own nodes.",
    2222: "Often an SSH on an alternate port, or a service console. Read the banner — if it's SSH, "
        "the same hardening rules as 22 apply.",
    2483: "Oracle over TLS — a database behind encryption. Same discipline as 1521: "
        "auth on, bind tight, never public.",
    3260: "iSCSI — block storage over the network. An open iSCSI target can hand a stranger a disk to read "
        "and write; restrict it to its storage network.",
    3690: "Subversion — version control over the wire. An open svnserve can leak source code; "
        "check the repo permissions.",
    4369: "Erlang Port Mapper — the directory for Erlang nodes (RabbitMQ, CouchDB). "
        "An open epmd lets an attacker enumerate and join the cluster; restrict it.",
    4444: "Unassigned — a service someone chose, and a famous backdoor port (Metasploit default). "
        "Identify the owning process first; an unexplained 4444 is a finding.",
    5601: "Kibana — the web UI for Elasticsearch. An open Kibana is a window into the indexed data; "
        "put auth in front of it.",
    5672: "AMQP — RabbitMQ's wire protocol. A message broker on the wire: check the credentials, "
        "and remember a broker that accepts anyone's messages is a spam relay.",
    5901: "VNC display :1 — a second desktop, same rules as 5900: weak shared password, no lockout, "
        "tunnel it or don't run it.",
    7001: "WebLogic — Oracle's app server admin. Historically a rich target (deserialization bugs); "
        "an open 7001 needs patching and strong credentials.",
    8086: "InfluxDB — a time-series database's API. An open InfluxDB can leak metrics and, in old versions, "
        "accept writes from anyone; require auth.",
    8081: "HTTP-alt — service consoles and proxies. Same rule as 8080: read the banner, check the auth.",
    8090: "HTTP-alt — service consoles. Same rule as 8080: read the banner, check the auth.",
    8500: "Consul — service discovery and configuration. An open Consul exposes the service map and, "
        "in old versions, lets anyone register services; restrict it.",
    9001: "Tor ORPort or a supervisor console — identify from the banner. A Tor relay port is expected on a relay; "
        "a supervisor console on 9001 with no auth is a finding.",
    9300: "Elasticsearch cluster protocol — node-to-node traffic. An open 9300 lets a stranger join the cluster; "
        "bind it to the cluster network only.",
    27018: "MongoDB shard — same discipline as 27017: auth on, bind to localhost.",
    992: "Telnet over TLS — the encrypted version of telnet. Better than 23, but telnet's trust model "
        "is still the problem; use SSH.",
    989: "FTPS data — the companion of 990. See the 990 explainer.",
    1025: "Often an RPC endpoint or a leftover listener. Identify the owning process — "
        "unexplained listeners on high ports are worth naming.",
    1026: "Often a calendar or RPC service. Identify the owning process.",
}


def service_name(port):
    return SERVICE.get(port, "unknown")


def explainer(port):
    """One-to-two lines per open port — the chip's teaching payload."""
    if port in EXPLAIN:
        return EXPLAIN[port]
    return (
        "Port %d (%s) is open and I don't have a specific brief for it. "
        "Unidentified listeners are worth naming: find the owning process "
        "(ss -tlnp on Linux), and if you can't name it, that IS the finding — "
        "close it or bind it to localhost until you can." % (port, service_name(port))
    )
