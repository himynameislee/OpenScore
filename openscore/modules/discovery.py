"""Asset discovery (passive): certificate transparency, subfinder, common names, DNS
resolution, ASN/hosting attribution and dangling-CNAME (subdomain takeover) detection."""
from __future__ import annotations

import ipaddress
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from .. import proof, util

log = logging.getLogger("openscore")
MODE = "passive"

COMMON = ["www", "mail", "webmail", "remote", "vpn", "sslvpn", "portal", "owa", "autodiscover",
          "sts", "adfs", "sso", "login", "api", "dev", "test", "staging", "admin", "ftp", "sftp",
          "citrix", "gateway", "rdweb", "rds", "rdp", "intranet", "extranet", "shop", "blog",
          "cpanel", "webdisk", "mx", "smtp", "secure", "app", "apps", "support", "help", "helpdesk",
          "status", "files", "cloud", "git", "gitlab", "jira", "confluence", "wiki", "crm", "hr",
          "exchange", "mdm", "fw", "firewall", "remote2", "vpn2", "dc", "ns1", "ns2", "backup",
          "nas", "camera", "cctv", "voip", "phone", "pbx", "meet", "owa2", "mail2", "m"]

# CNAME suffix -> service. Takeover is possible when the CNAME target no longer resolves.
TAKEOVER = {
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Service",
    "cloudapp.azure.com": "Azure VM", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob", "azureedge.net": "Azure CDN",
    "azurefd.net": "Azure Front Door", "azure-api.net": "Azure API Mgmt",
    "azurecontainer.io": "Azure Container", "azurestaticapps.net": "Azure Static Web Apps",
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3 website", "elasticbeanstalk.com": "AWS Beanstalk",
    "cloudfront.net": "AWS CloudFront", "github.io": "GitHub Pages", "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku", "netlify.app": "Netlify", "pantheonsite.io": "Pantheon",
    "zendesk.com": "Zendesk", "helpscoutdocs.com": "HelpScout", "ghost.io": "Ghost",
    "myshopify.com": "Shopify", "surge.sh": "Surge", "bitbucket.io": "Bitbucket",
    "wordpress.com": "WordPress.com", "fly.dev": "Fly.io", "readme.io": "ReadMe",
    "webflow.io": "Webflow", "unbouncepages.com": "Unbounce", "wpengine.com": "WP Engine",
}

# How many DNS labels in front of the suffix the customer chooses when creating the resource.
# A dangling target of any other shape can't simply be re-registered: the provider assigns those
# names itself (random IDs, hashes, region labels). 0 = the provider always assigns the name.
# Suffixes not listed here keep the plain "possible takeover" finding.
CLAIM_LABELS = {
    "trafficmanager.net": 1,      # the relative DNS name is one label: <name>.trafficmanager.net
    "azurewebsites.net": 1,       # <app>.azurewebsites.net; "unique default hostnames"
                                  # (<app>-<hash>.<region>-01.azurewebsites.net) can't be re-created
    "cloudapp.net": 1,
    "cloudapp.azure.com": 2,      # <label>.<region>.cloudapp.azure.com
    "blob.core.windows.net": 1,
    "azure-api.net": 1,
    "azureedge.net": 1,
    "azurefd.net": 1,             # classic Front Door; Standard/Premium add a hash (<name>-<hash>.z01.azurefd.net)
    "azurecontainer.io": 2,       # <label>.<region>.azurecontainer.io
    "azurestaticapps.net": 0,     # generated names (<words>-<hash>[.<n>].azurestaticapps.net)
    "cloudfront.net": 0,          # d<id>.cloudfront.net is assigned by AWS
    "herokudns.com": 0,           # <id>.herokudns.com is assigned by Heroku
    "elasticbeanstalk.com": 2,    # <name>.<region>.elasticbeanstalk.com
}


def takeover_service(target: str) -> tuple[str, str] | None:
    """(suffix, service) for a CNAME target, matched on whole labels (not substrings)."""
    target = target.rstrip(".").lower()
    for suf, svc in TAKEOVER.items():
        if suf == "s3-website":   # bucket.s3-website-<region>.amazonaws.com / bucket.s3-website.<region>...
            if target.endswith(".amazonaws.com") and any(
                    l == "s3-website" or l.startswith("s3-website-") for l in target.split(".")):
                return suf, svc
            continue
        if target == suf or target.endswith("." + suf):
            return suf, svc
    return None


def claimable(target: str, suffix: str) -> bool | None:
    """True/False when the target's shape is known for this provider; None when it isn't."""
    want = CLAIM_LABELS.get(suffix)
    if want is None:
        return None
    labels = target.rstrip(".").lower()[: -len(suffix)].rstrip(".").split(".")
    return want > 0 and len(labels) == want and all(labels)

# ASN org substrings -> hosting class. "saas" = third-party service the organization uses but
# doesn't run (scored and labeled with the vendor; no active checks); "cdn" = proxy in front of your origin (no port
# scans); "cloud" = IaaS/PaaS you run and configure yourself (fully assessed).
# Microsoft's ASN carries both Microsoft 365 and customers' own Azure VMs, gateways and apps. Azure is
# the customer's to fix, so the ASN means "cloud"; Microsoft 365 is recognized by CNAME (SAAS_CNAMES).
# Order matters: first match wins ("akamai connected cloud" before "akamai").
HOSTING = [
    ("akamai connected cloud", "cloud"),
    ("cloudflare", "cdn"), ("akamai", "cdn"), ("fastly", "cdn"), ("incapsula", "cdn"),
    ("imperva", "cdn"), ("stackpath", "cdn"), ("sucuri", "cdn"), ("edgecast", "cdn"),
    ("microsoft", "cloud"), ("google", "cloud"), ("amazon", "cloud"), ("digitalocean", "cloud"),
    ("linode", "cloud"), ("ovh", "cloud"), ("hetzner", "cloud"),
    ("vultr", "cloud"), ("oracle", "cloud"), ("salesforce", "saas"), ("shopify", "saas"),
    ("squarespace", "saas"), ("wix", "saas"), ("hubspot", "saas"), ("automattic", "saas"),
    ("godaddy", "cloud"), ("zendesk", "saas"), ("atlassian", "saas"), ("mimecast", "saas"),
    ("proofpoint", "saas"), ("barracuda", "saas"), ("zscaler", "saas"), ("okta", "saas"),
    # email / marketing senders: their IPs show up as o1.<domain> etc. and must never be port-scanned
    ("sendgrid", "saas"), ("twilio", "saas"), ("rocket science", "saas"), ("mailgun", "saas"),
    ("sparkpost", "saas"), ("messagebird", "saas"), ("postmark", "saas"), ("wildbit", "saas"),
    ("constant contact", "saas"), ("mailjet", "saas"), ("sendinblue", "saas"), ("brevo", "saas"),
    ("marketo", "saas"), ("github", "saas"), ("netlify", "saas"), ("vercel", "saas"),
]
# CNAME target suffixes that mean "a SaaS provider serves this host", regardless of the IP's ASN.
# Matched as DNS suffixes (exact name or ".suffix"), not substrings.
SAAS_CNAMES = ["outlook.com", "office.com", "office365.com", "lync.com", "microsoftonline.com",
               "manage.microsoft.com", "protection.outlook.com", "sharepoint.com", "msappproxy.net",
               "zendesk.com", "hubspot.net", "salesforce.com", "force.com", "pardot.com",
               "shopify.com", "squarespace.com", "wixdns.net", "googlehosted.com", "ghs.google.com",
               "mailgun.org", "sendgrid.net", "mandrillapp.com", "sparkpostmail.com", "mktoweb.com",
               # identity providers: they run TLS, cookies and headers on your custom login domain
               "okta.com", "oktapreview.com", "okta-emea.com", "okta-dnssec.com", "auth0.com",
               "safebase.io", "statuspage.io", "freshdesk.com", "helpscoutdocs.com", "okt.to",
               "github.io", "netlify.app", "vercel-dns.com", "pphosted.com", "mimecast.com"]
# Address ranges that belong to a SaaS provider even though another network announces them (so the
# ASN org names the CDN, not the provider). Root domains can't use a CNAME, so a provider-hosted apex
# is only recognizable by its A/AAAA records. Only ranges the provider documents or that are
# provably theirs; first match wins.
SAAS_IP_RANGES = [
    ("199.60.103.0/24", "HubSpot"),                 # root-domain A records; announced via Cloudflare AS209242
    ("2606:2c40::c73c:6700/120", "HubSpot"),        # IPv6 twins of 199.60.103.x
    ("23.227.38.0/24", "Shopify"),                  # Shopify's documented apex A record (23.227.38.65)
    ("75.2.60.5/32", "Netlify"),                    # Netlify's documented apex load balancer
    ("76.76.21.21/32", "Vercel"),                   # Vercel's documented apex A record
]
_SAAS_NETS = [(ipaddress.ip_network(n), p) for n, p in SAAS_IP_RANGES]


def saas_provider_for_ip(ip: str) -> str:
    """Provider name if the address is in a known SaaS range, else ""."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return next((p for net, p in _SAAS_NETS if addr.version == net.version and addr in net), "")


# Friendly vendor names for SAAS_CNAMES / CDN_CNAMES suffixes (report labels "hosted by ...").
VENDOR_BY_SUFFIX = {
    "outlook.com": "Microsoft 365", "office.com": "Microsoft 365", "office365.com": "Microsoft 365",
    "lync.com": "Microsoft 365", "microsoftonline.com": "Microsoft 365", "protection.outlook.com": "Microsoft 365",
    "sharepoint.com": "Microsoft 365", "manage.microsoft.com": "Microsoft Intune", "msappproxy.net": "Microsoft Entra",
    "zendesk.com": "Zendesk", "hubspot.net": "HubSpot", "salesforce.com": "Salesforce", "force.com": "Salesforce",
    "pardot.com": "Salesforce Pardot", "shopify.com": "Shopify", "squarespace.com": "Squarespace", "wixdns.net": "Wix",
    "googlehosted.com": "Google", "ghs.google.com": "Google", "mailgun.org": "Mailgun", "sendgrid.net": "SendGrid",
    "mandrillapp.com": "Mailchimp", "sparkpostmail.com": "SparkPost", "mktoweb.com": "Marketo",
    "okta.com": "Okta", "oktapreview.com": "Okta", "okta-emea.com": "Okta", "okta-dnssec.com": "Okta", "okt.to": "Okta",
    "auth0.com": "Auth0", "safebase.io": "SafeBase", "statuspage.io": "Atlassian Statuspage",
    "freshdesk.com": "Freshdesk", "helpscoutdocs.com": "Help Scout", "github.io": "GitHub Pages",
    "netlify.app": "Netlify", "vercel-dns.com": "Vercel", "pphosted.com": "Proofpoint", "mimecast.com": "Mimecast",
    "azurefd.net": "Azure Front Door", "azureedge.net": "Azure CDN", "cloudfront.net": "Amazon CloudFront",
    "akamaiedge.net": "Akamai", "edgekey.net": "Akamai", "edgesuite.net": "Akamai", "fastly.net": "Fastly",
    "cdn.cloudflare.net": "Cloudflare", "impervadns.net": "Imperva",
}


def _org_name(org: str) -> str:
    """'PROOFPOINT-ASN-US-WEST - Proofpoint, Inc., US' -> 'Proofpoint, Inc.'"""
    org = (org or "").strip()
    if " - " in org:
        org = org.split(" - ", 1)[1]
    parts = [p.strip() for p in org.split(",")]
    if len(parts) > 1 and len(parts[-1]) == 2:      # trailing country code
        parts = parts[:-1]
    return ", ".join(parts)


def vendor_for(asset) -> str:
    """Who runs a SaaS- or CDN-hosted asset, for the report ("hosted by HubSpot"). "" for the
    organization's own hosts (owned/cloud)."""
    if asset is None or asset.hosting_class not in ("saas", "cdn"):
        return ""
    for h in (asset.hosting or {}).values():
        if h.get("provider"):
            return h["provider"]
    for c in reversed(asset.cnames or []):
        c = c.lower().rstrip(".")
        for suffix, name in VENDOR_BY_SUFFIX.items():
            if c == suffix or c.endswith("." + suffix):
                return name
    for h in (asset.hosting or {}).values():
        if h.get("class") == asset.hosting_class and h.get("org"):
            return _org_name(h["org"])
    return "a SaaS provider" if asset.hosting_class == "saas" else "a CDN"


# CNAME target suffixes for edge/CDN services (no port scans; headers still assessed).
CDN_CNAMES = ["azurefd.net", "azureedge.net", "afd.azureedge.net", "cloudfront.net", "akamaiedge.net",
              "edgekey.net", "edgesuite.net", "fastly.net", "cdn.cloudflare.net", "impervadns.net"]


def class_for_org(org: str) -> str:
    """Hosting class from an ASN org name. Unknown orgs (dedicated/colo hosting) count as owned."""
    org = (org or "").lower()
    return next((c for k, c in HOSTING if k in org), "owned" if org else "unknown")


def _suffix_match(name: str, suffixes) -> bool:
    name = name.lower().rstrip(".")
    return any(name == s or name.endswith("." + s) for s in suffixes)


def classify(cnames, ip_classes: set, is_ip: bool = False) -> str:
    """Hosting class for an asset from its CNAME chain and the classes of its IPs' ASNs."""
    if any(_suffix_match(c, SAAS_CNAMES) for c in cnames):
        return "saas"
    if any(_suffix_match(c, CDN_CNAMES) for c in cnames):
        return "cdn"
    if "saas" in ip_classes and len(ip_classes) == 1:
        return "saas"
    for cls in ("cdn", "cloud", "owned"):
        if cls in ip_classes:
            return cls
    return "owned" if is_ip else "unknown"


CRTSH_BACKOFF = (5, 15)   # seconds before retries 2 and 3; crt.sh often answers 429/502/503 under load


def _crtsh(ctx) -> set[str]:
    url = f"https://crt.sh/?q=%25.{ctx.domain}&output=json"
    err, r = None, None
    for attempt in range(len(CRTSH_BACKOFF) + 1):
        if attempt:
            wait = CRTSH_BACKOFF[attempt - 1]
            ra = str((r.headers if r is not None else {}).get("Retry-After", ""))
            if ra.isdigit():
                wait = min(int(ra), 30)
            log.info("crt.sh: retrying in %ds (%s)", wait, err)
            time.sleep(wait)
        r = None
        try:
            r = ctx.session.get(url, timeout=60)
            if r.status_code != 200:
                err = RuntimeError(f"HTTP {r.status_code}")
                # crt.sh's query URL never legitimately 404s; under load its front end answers
                # 404/429/5xx, so all of those are worth a retry
                if r.status_code in (404, 429) or r.status_code >= 500:
                    continue
                break
            names = set()
            for row in json.loads(r.text or "[]"):
                for n in str(row.get("name_value", "")).splitlines():
                    names.add(n.strip().lower().lstrip("*."))
            log.info("crt.sh: %d names", len(names))
            return names
        except Exception as e:      # timeouts, resets, an HTML error page instead of JSON
            err = e
    log.warning("crt.sh failed: %s — discovery relies on %s", err,
                "subfinder and common hostnames" if util.which("subfinder")
                else "common hostnames only (subfinder isn't installed)")
    util.note_source_failure(ctx, "discovery", "crt.sh", err)
    return set()


def _subfinder(ctx) -> set[str]:
    if not util.which("subfinder"):
        return set()
    rc, out, err = util.run(["subfinder", "-d", ctx.domain, "-silent", "-all", "-timeout", "30"], timeout=300)
    names = {l.strip().lower() for l in out.splitlines() if l.strip()}
    log.info("subfinder: %d names", len(names))
    return names


def _resolve(ctx, host: str) -> dict:
    out = {"host": host, "cnames": [], "ips": [], "status": "ok"}
    name = host
    for _ in range(8):  # follow CNAME chain
        r = ctx.dns.query(name, "CNAME")
        if r.ok and r.records:
            name = r.records[0].lower()
            out["cnames"].append(name)
        else:
            break
    a = ctx.dns.query(host, "A")
    aaaa = ctx.dns.query(host, "AAAA")
    out["ips"] = (a.records if a.ok else []) + (aaaa.records if aaaa.ok else [])
    if not out["ips"]:
        if a.status == "error":
            out["status"] = "error"
        elif out["cnames"]:
            tail = ctx.dns.query(out["cnames"][-1], "A")
            out["status"] = "dangling" if tail.status == "nxdomain" else "noip"
        else:
            out["status"] = a.status
    return out


def _asn(ctx, ip: str) -> dict:
    """Team Cymru IP->ASN over DNS (free, no key)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nib = addr.exploded.replace(":", "")
        q = ".".join(reversed(nib)) + ".origin6.asn.cymru.com"
    r = ctx.dns.txt(q)
    if not r.ok or not r.records:
        provider = saas_provider_for_ip(ip)
        return {"class": "saas", "provider": provider} if provider else {}
    parts = [p.strip() for p in r.records[0].split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else ""
    info = {"asn": asn, "prefix": parts[1] if len(parts) > 1 else "", "cc": parts[2] if len(parts) > 2 else ""}
    if asn:
        n = ctx.dns.txt(f"AS{asn}.asn.cymru.com")
        if n.ok and n.records:
            info["org"] = n.records[0].split("|")[-1].strip()
    org = info.get("org", "").lower()
    info["class"] = class_for_org(org)
    provider = saas_provider_for_ip(ip)
    if provider:
        info["class"], info["provider"] = "saas", provider
    return info


def _dangling(ctx, h: str, cnames: list[str]) -> None:
    target = cnames[-1].rstrip(".")
    a = ctx.asset(h)
    a.cnames = cnames
    a.sources.add("dns")
    chain = [h] + cnames
    lines = [[f"{chain[i]}.  CNAME  {chain[i + 1]}.", None, None] for i in range(len(chain) - 1)]
    match = takeover_service(target)
    svc = match[1] if match else None
    can = claimable(target, match[0]) if match else None
    if match and can is not False:
        lines.append([f"{target}.  A  ;; NXDOMAIN", "bad", f"{svc} resource no longer exists"])
        if match[0] == "trafficmanager.net":
            name = target[: -len(".trafficmanager.net")]
            lines.append([f"read-only availability check: az network traffic-manager profile check-dns "
                          f"--name {name}", None, "nameAvailable: true = anyone can claim it"])
        ctx.add("dns_dangling_cname", h, f"{h} → CNAME {target} ({svc}) returns NXDOMAIN",
                source="discovery",
                proof=proof.make("CNAME chain resolution", f"dig {h} +trace-cname", lines,
                                 verdict=f"{h} points at an unclaimed {svc} name"))
        return
    if match:
        why = (f"{svc} assigns names of this shape itself, so the name can't simply be re-registered"
               if CLAIM_LABELS.get(match[0]) else f"{svc} assigns these names itself")
    else:
        why = "not a known cloud service; if the target's own domain has expired, check who can register it"
    lines.append([f"{target}.  A  ;; NXDOMAIN", "warn", "target no longer exists"])
    lines.append([why, None, None])
    ctx.add("dns_dangling_cname_stale", h,
            f"{h} → CNAME {target}" + (f" ({svc})" if svc else "") + f" returns NXDOMAIN; {why}",
            source="discovery",
            proof=proof.make("CNAME chain resolution", f"dig {h} +trace-cname", lines,
                             verdict=f"{h} is a stale DNS record (target gone, not directly claimable)"))


def run(ctx) -> None:
    cfg = ctx.cfg
    names = {ctx.domain, "www." + ctx.domain}
    if not cfg.no_discovery:
        names |= _crtsh(ctx)
        names |= _subfinder(ctx)
        names |= {f"{c}.{ctx.domain}" for c in COMMON}
    names = {n for n in names if n and (n == ctx.domain or n.endswith("." + ctx.domain))
             and n not in cfg.exclude and "*" not in n}
    log.info("Resolving %d candidate hostnames", len(names))

    with ThreadPoolExecutor(max_workers=cfg.threads * 2) as ex:
        results = list(ex.map(lambda h: _resolve(ctx, h), sorted(names)))

    live = []
    for res in results:
        h = res["host"]
        if res["status"] == "dangling":
            _dangling(ctx, h, res["cnames"])
            continue
        if res["ips"]:
            live.append(res)

    # prioritize: apex, www, mail/remote-access names, then shortest names
    prio = {"": 0, "www": 1, "mail": 2, "remote": 2, "vpn": 2, "owa": 2, "portal": 3}
    def rank(r):
        sub = r["host"][: -len(ctx.domain)].rstrip(".")
        return (prio.get(sub, 5), len(r["host"]), r["host"])
    live.sort(key=rank)
    if len(live) > cfg.max_hosts:
        log.warning("Discovered %d live hosts; keeping first %d (use --max-hosts)", len(live), cfg.max_hosts)
        live = live[: cfg.max_hosts]

    for res in live:
        a = ctx.asset(res["host"])
        a.ips = res["ips"]
        a.cnames = res["cnames"]
        a.sources.add("dns")

    # Operator-supplied hosts / URLs / IPs
    for h in cfg.hosts:
        a = ctx.asset(h)
        a.explicit = True
        a.sources.add("operator")
        if util.is_ip(h):
            a.ips = [h]
        elif not a.ips:
            res = _resolve(ctx, h)
            a.ips = res["ips"]
    for u in cfg.urls:
        p = urlparse(u)
        a = ctx.asset(p.hostname)
        a.explicit = True
        a.sources.add("operator")
        a.web.setdefault(u, {})
        if util.is_ip(p.hostname):
            a.ips = [p.hostname]
        elif not a.ips:
            a.ips = _resolve(ctx, p.hostname)["ips"]
    for net in cfg.ip_ranges:
        if net.num_addresses > 256:
            log.warning("Range %s larger than /24 — only first 256 addresses used", net)
        for i, ip in enumerate(net.hosts() if net.num_addresses > 2 else net):
            if i >= 256:
                break
            a = ctx.asset(str(ip))
            a.ips = [str(ip)]
            a.explicit = True
            a.sources.add("operator-range")

    # Hosting attribution
    ips = ctx.all_ips()
    with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
        asn = dict(zip(ips, ex.map(lambda ip: _asn(ctx, ip), ips)))
    for a in ctx.assets.values():
        a.hosting = {ip: asn.get(ip, {}) for ip in a.ips}
        classes = {v.get("class", "unknown") for v in a.hosting.values()} or {"unknown"}
        a.hosting_class = classify(a.cnames, classes, util.is_ip(a.host))

    log.info("Inventory: %d hosts, %d IPs", len(ctx.assets), len(ips))
