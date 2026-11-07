"""Port exposure (ACTIVE). Uses nmap when installed (service/version detection), otherwise a
built-in TCP connect scan of high-risk ports. Shared port→risk mapping is also used by the
passive Shodan InternetDB lookup in reputation.py."""
from __future__ import annotations

import logging
import re
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .. import util

log = logging.getLogger("openscore")
MODE = "active"

# port -> (check_id, label)
PORT_MAP = {
    21: ("net_exposed_ftp", "FTP"), 23: ("net_exposed_telnet", "Telnet"),
    22: ("net_exposed_ssh", "SSH"), 2222: ("net_exposed_ssh", "SSH (alt)"),
    110: ("net_exposed_cleartext_mail", "POP3"), 143: ("net_exposed_cleartext_mail", "IMAP"),
    135: ("net_exposed_smb", "MS-RPC"), 137: ("net_exposed_smb", "NetBIOS-NS"),
    139: ("net_exposed_smb", "NetBIOS-SSN"), 445: ("net_exposed_smb", "SMB"),
    3389: ("net_exposed_rdp", "RDP"),
    389: ("net_exposed_ldap", "LDAP"), 636: ("net_exposed_ldap", "LDAPS"), 3268: ("net_exposed_ldap", "AD Global Catalog"),
    3269: ("net_exposed_ldap", "AD Global Catalog SSL"), 88: ("net_exposed_ldap", "Kerberos"),
    1433: ("net_exposed_db", "MS SQL Server"), 1434: ("net_exposed_db", "MS SQL Browser"),
    3306: ("net_exposed_db", "MySQL/MariaDB"), 5432: ("net_exposed_db", "PostgreSQL"),
    1521: ("net_exposed_db", "Oracle DB"), 50000: ("net_exposed_db", "DB2"),
    6379: ("net_exposed_datastore", "Redis"), 27017: ("net_exposed_datastore", "MongoDB"),
    27018: ("net_exposed_datastore", "MongoDB"), 9200: ("net_exposed_datastore", "Elasticsearch"),
    9300: ("net_exposed_datastore", "Elasticsearch transport"), 11211: ("net_exposed_datastore", "Memcached"),
    5984: ("net_exposed_datastore", "CouchDB"), 9042: ("net_exposed_datastore", "Cassandra"),
    2375: ("net_exposed_docker", "Docker API"), 2376: ("net_exposed_docker", "Docker API (TLS)"),
    6443: ("net_exposed_docker", "Kubernetes API"), 10250: ("net_exposed_docker", "Kubelet"),
    2379: ("net_exposed_docker", "etcd"),
    5900: ("net_exposed_remote_admin", "VNC"), 5901: ("net_exposed_remote_admin", "VNC"),
    5985: ("net_exposed_remote_admin", "WinRM"), 5986: ("net_exposed_remote_admin", "WinRM (HTTPS)"),
    161: ("net_exposed_remote_admin", "SNMP"), 623: ("net_exposed_remote_admin", "IPMI"),
    10000: ("net_exposed_admin_web", "Webmin"), 5601: ("net_exposed_admin_web", "Kibana"),
    8443: ("net_exposed_admin_web", "HTTPS-alt / mgmt UI"), 4443: ("net_exposed_admin_web", "HTTPS-alt / mgmt UI"),
    10443: ("net_exposed_admin_web", "Fortinet/HTTPS mgmt"), 8006: ("net_exposed_admin_web", "Proxmox"),
    902: ("net_exposed_admin_web", "VMware ESXi"), 9443: ("net_exposed_admin_web", "HTTPS-alt / mgmt UI"),
    2082: ("net_exposed_admin_web", "cPanel"), 2083: ("net_exposed_admin_web", "cPanel"),
    2086: ("net_exposed_admin_web", "WHM"), 2087: ("net_exposed_admin_web", "WHM"),
    8080: ("net_exposed_other", "HTTP-alt"), 8000: ("net_exposed_other", "HTTP-alt"),
    8888: ("net_exposed_other", "HTTP-alt"), 1723: ("net_exposed_other", "PPTP VPN"),
    1194: ("net_exposed_other", "OpenVPN"), 5060: ("net_exposed_other", "SIP"),
    111: ("net_exposed_remote_admin", "RPCbind"), 2049: ("net_exposed_remote_admin", "NFS"),
    873: ("net_exposed_remote_admin", "rsync"), 512: ("net_exposed_telnet", "rexec"),
    513: ("net_exposed_telnet", "rlogin"), 514: ("net_exposed_telnet", "rsh"),
}
EXPECTED = {80, 443, 25, 465, 587, 993, 995, 53}   # normal for web/mail/DNS hosts
FALLBACK_PORTS = sorted(set(PORT_MAP) | EXPECTED)


def classify(port: int):
    """Return (check_id, label) or None for expected web/mail ports."""
    if port in EXPECTED:
        return None
    return PORT_MAP.get(port, ("net_exposed_other", f"tcp/{port}"))


def report_port(ctx, ip: str, port: int, service: str = "", source: str = "",
                confidence: str = "firm", shodan_ports=None) -> None:
    c = classify(port)
    if not c:
        return
    check_id, label = c
    hosts = sorted(a.host for a in ctx.assets.values() if ip in a.ips and a.host != ip)
    ev = f"{ip}:{port}/tcp {service}".strip() + (f"\nHostnames: {', '.join(hosts[:8])}" if hosts else "")
    from .. import kb
    from .. import proof
    if source == "shodan-internetdb":
        pr = proof.make("Shodan InternetDB (passive)", f"curl -s https://internetdb.shodan.io/{ip}",
                        [[f'"ports": [{", ".join(str(p) for p in sorted(shodan_ports or [port]))}]', "warn",
                          f"{port} = {label} seen open by Shodan's scanners (not yet live-verified)"]]
                        + ([[f"hostnames: {', '.join(hosts[:6])}", None, None]] if hosts else []),
                        verdict=f"Shodan observed {label} on {ip}:{port}")
    elif source == "nmap":
        pr = proof.make("Port scan", f"nmap -Pn -sT -sV -p {port} {ip}",
                        [["PORT      STATE  SERVICE / VERSION", None, None],
                         [f"{str(port) + '/tcp':<9} open   {service}", "bad", f"{label} reachable from the internet"]],
                        verdict=f"{label} answered on {ip}:{port}")
    else:
        pr = proof.make("TCP connect test", f"nc -vz {ip} {port}",
                        [[f"Connection to {ip} {port} port [tcp/*] succeeded!", "bad",
                          f"{label} reachable from the internet"]],
                        verdict=f"{ip}:{port} accepted a TCP connection")
    ctx.add(check_id, ip, ev, title=f"{kb.get(check_id)['title']} — {label} (tcp/{port})", source=source,
            confidence=confidence, proof=pr)


def _nmap(ctx, ips: list[str]) -> bool:
    """nmap TCP connect scan + light version detection.

    nmap's --top-ports list is about general popularity and leaves out many of the ports this
    module exists to flag (Redis 6379, MongoDB 27017, Docker 2375, Kubelet 10250, WinRM 5985,
    Memcached 11211 ...). So unless every port is scanned (--full-ports), run a second, short pass
    over PORT_MAP + EXPECTED. nmap can't union --top-ports with -p in one run."""
    if not util.which("nmap"):
        return False
    base = ["nmap", "-Pn", "-sT", "-sV", "--version-light", "--open", "-T3",
            "--max-retries", "2", "--host-timeout", "15m", "-oX", "-"]
    if ctx.cfg.full_ports:
        passes = [("all ports", ["-p-"])]
    else:
        passes = [("top 1000 ports", ["--top-ports", "1000"]),
                  (f"{len(FALLBACK_PORTS)} high-risk ports", ["-p", ",".join(map(str, FALLBACK_PORTS))])]
    for label, spec in passes:
        cmd = base + spec + ips
        ctx.audit_log(f"nmap {' '.join(cmd[1:-len(ips)])} ({label}) on {len(ips)} IPs: {', '.join(ips)}")
        rc, out, err = util.run(cmd, timeout=7200)
        if rc != 0 or not out.strip():
            log.warning("nmap failed (%s): %s — falling back to built-in scan", rc, err.strip()[:200])
            return False      # built-in scan covers every PORT_MAP port; findings so far are kept
        _parse_nmap(ctx, out)
    return True


def _parse_nmap(ctx, xml: str) -> None:
    root = ET.fromstring(xml)
    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        for p in host.findall("ports/port"):
            if p.find("state").get("state") != "open":
                continue
            port = int(p.get("portid"))
            svc = p.find("service")
            desc = ""
            if svc is not None:
                prod, ver = svc.get("product", ""), svc.get("version", "")
                desc = " ".join(x for x in (svc.get("name", ""), prod, ver) if x)
                if prod and ver:
                    ctx.record_software(addr, prod, ver, "nmap -sV", raw=svc.get("extrainfo", ""))
                for cpe in svc.findall("cpe"):
                    _cpe_software(ctx, addr, cpe.text or "", "nmap cpe")
            report_port(ctx, addr, port, desc, "nmap")


def _cpe_software(ctx, asset, cpe: str, src: str):
    parts = cpe.replace("cpe:/", "cpe:2.3:").split(":")
    # cpe:2.3:a:vendor:product:version
    if len(parts) >= 6 and parts[5] not in ("", "*", "-"):
        ctx.record_software(asset, parts[4], parts[5], src)


def _connect(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _builtin(ctx, ips: list[str]) -> None:
    ctx.audit_log(f"built-in TCP connect scan of {len(FALLBACK_PORTS)} ports on {', '.join(ips)}")
    jobs = [(ip, p) for ip in ips for p in FALLBACK_PORTS]
    with ThreadPoolExecutor(max_workers=min(64, ctx.cfg.threads * 8)) as ex:
        results = ex.map(lambda j: (j, _connect(j[0], j[1], 2.0)), jobs)
        for (ip, port), ok in results:
            if ok:
                report_port(ctx, ip, port, "", "tcp-connect")


def run(ctx) -> None:
    ips = []
    skipped = []
    for a in ctx.assets.values():
        if a.hosting_class in ("cdn", "saas") and not a.explicit and not ctx.cfg.scan_cdn:
            skipped += a.ips
            continue
        if not ctx.in_scope(a.host):
            continue
        ips += [ip for ip in a.ips if ":" not in ip]  # IPv4 only for now
    shared = set(skipped)
    ips = sorted(set(ips) - shared)
    if shared:
        ctx.module_status.setdefault("ports", {})["skipped_cdn_saas_ips"] = sorted(shared)
    if not ips:
        log.info("No in-scope IPs to port scan")
        return
    log.info("Port scanning %d IPs", len(ips))
    if not _nmap(ctx, ips):
        _builtin(ctx, ips)
    confirm_passive_ports(ctx, set(ips))


PORT_IN_TITLE = re.compile(r"\(tcp/(\d+)\)")


def confirm_passive_ports(ctx, scanned: set[str]) -> None:
    """Shodan InternetDB data can be days or weeks old. For every port it reported on an IP we
    are authorized to scan, try a live TCP connect: confirmed → firm; unreachable → keep as
    tentative with a note (stale data, or the port is source-IP restricted)."""
    stale = []
    for f in list(ctx.findings):
        if f.factor != "network" or f.confidence != "tentative" or f.asset not in scanned:
            continue
        m = PORT_IN_TITLE.search(f.title)
        if not m:
            continue
        port = int(m.group(1))
        if _connect(f.asset, port, 3.0) or _connect(f.asset, port, 5.0):
            f.confidence = "firm"
            f.source += ", live-confirmed"
            if f.proof:
                f.proof["lines"] += [["", None, None], [f"$ nc -vz {f.asset} {port}", "cmd", None],
                                     [f"Connection to {f.asset} {port} port [tcp/*] succeeded!", "bad",
                                      "confirmed live by OpenScore"]]
        else:
            if f.proof:
                f.proof["lines"] += [["", None, None], [f"$ nc -vz -w 5 {f.asset} {port}", "cmd", None],
                                     [f"nc: connect to {f.asset} port {port} (tcp) timed out", "good",
                                      "not reachable from this scanner — Shodan data may be stale"]]
            f.evidence += ("\nNOT reachable from this scanner during the live scan — Shodan data is "
                           "likely stale, or the port is restricted to specific source IPs.")
            stale.append(f"{f.asset}:{port}")
    if stale:
        ctx.module_status.setdefault("ports", {})["shodan_ports_not_confirmed"] = stale
