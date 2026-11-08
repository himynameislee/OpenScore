"""Remediation knowledge base.

Every check a module can emit is described here: which factor it scores under, the default
severity, a plain-English explanation and concrete remediation steps (with Microsoft 365 /
Entra specifics where relevant, since many organizations run on Microsoft 365).
"""
from __future__ import annotations

FACTORS = {
    "network":    {"name": "Network Security",       "weight": 1.0,
                   "desc": "Risky services reachable from the internet (RDP, SMB, databases, remote admin)."},
    "patching":   {"name": "Patching Cadence",       "weight": 1.0,
                   "desc": "End-of-life or outdated software and known-vulnerable versions (CISA KEV / EPSS)."},
    "exposure":   {"name": "Information Exposure",   "weight": 1.0,
                   "desc": "Leaked files, debug pages, version banners and breached accounts."},
    "reputation": {"name": "IP & Domain Reputation", "weight": 0.9,
                   "desc": "Blocklist listings, abuse reports and signs of compromised hosts."},
    "appsec":     {"name": "Application Security",   "weight": 0.8,
                   "desc": "HTTP security headers, cookie flags, HTTPS redirects, CORS."},
    "tls":        {"name": "TLS / Certificates",     "weight": 0.8,
                   "desc": "Certificate validity, protocol versions, key strength."},
    "email":      {"name": "Email Security",         "weight": 0.8,
                   "desc": "SPF, DKIM, DMARC, MTA-STS — spoofing and phishing resistance."},
    "dns":        {"name": "DNS Health",             "weight": 0.6,
                   "desc": "DNSSEC, CAA, nameserver resilience, zone transfers, subdomain takeover."},
}

_M365_DKIM = (
    "Microsoft 365: Defender portal → Email & collaboration → Policies → Threat policies → "
    "Email authentication settings → DKIM → select the domain → publish the two CNAMEs shown "
    "(selector1._domainkey / selector2._domainkey → *.onmicrosoft.com) → toggle 'Sign messages "
    "for this domain with DKIM signatures' ON. PowerShell: New-DkimSigningConfig -DomainName "
    "<domain> -Enabled $true"
)

CHECKS: dict[str, dict] = {
    # ------------------------------------------------------------------ EMAIL
    "email_spf_missing": dict(
        factor="email", severity="high", title="No SPF record",
        description="Without SPF, receiving mail servers cannot tell which servers may send mail "
                    "for this domain, which makes spoofing it trivial.",
        remediation="Publish one TXT record at the domain apex. M365 only: "
                    "`v=spf1 include:spf.protection.outlook.com -all`. Add includes for every other "
                    "sender (marketing, CRM, ticketing). If the domain never sends mail: `v=spf1 -all`.",
        refs=["https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure"]),
    "email_spf_multiple": dict(
        factor="email", severity="high", title="Multiple SPF records (SPF permerror)",
        description="RFC 7208 allows exactly one v=spf1 record. With two or more, receivers treat "
                    "SPF as a permanent error and it provides no protection.",
        remediation="Merge all mechanisms into a single `v=spf1 ... -all` TXT record and delete the rest.",
        refs=["https://www.rfc-editor.org/rfc/rfc7208#section-4.5"]),
    "email_spf_permissive": dict(
        factor="email", severity="high", title="SPF allows any sender (+all / ?all)",
        description="`+all` authorizes every server on the internet; `?all` is neutral. Either "
                    "defeats SPF.",
        remediation="End the record with `-all` (hard fail) or at minimum `~all` while DMARC is in monitoring.",
        refs=[]),
    "email_spf_softfail": dict(
        factor="email", severity="low", title="SPF uses soft-fail (~all)",
        description="`~all` is common and acceptable when DMARC is enforced, but `-all` is stronger "
                    "and tells receivers to reject unlisted senders.",
        remediation="Once all legitimate senders are listed and DMARC reports are clean, change `~all` to `-all`.",
        refs=[]),
    "email_spf_too_many_lookups": dict(
        factor="email", severity="medium", title="SPF exceeds 10 DNS lookups",
        description="SPF evaluation is limited to 10 DNS-querying mechanisms (include, a, mx, ptr, "
                    "exists, redirect). Beyond that receivers return permerror and SPF fails.",
        remediation="Remove unused includes, replace `a`/`mx` with ip4/ip6 ranges, or move bulk "
                    "senders to a subdomain (e.g. mail.example.com) with its own SPF.",
        refs=["https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"]),
    "email_spf_ptr": dict(
        factor="email", severity="low", title="SPF uses deprecated 'ptr' mechanism",
        description="`ptr` is slow, unreliable and deprecated; many receivers ignore it.",
        remediation="Replace `ptr` with explicit ip4/ip6 ranges or includes.", refs=[]),
    "email_spf_ok": dict(factor="email", severity="pass", title="SPF record valid and enforcing",
                         description="", remediation="", refs=[]),
    "email_dmarc_missing": dict(
        factor="email", severity="high", title="No DMARC record",
        description="DMARC tells receivers what to do when SPF/DKIM fail and sends you reports. "
                    "Without it, spoofed mail claiming to be from this domain is usually delivered.",
        remediation="Start in monitoring: TXT `_dmarc.<domain>` = `v=DMARC1; p=none; "
                    "rua=mailto:dmarc@<domain>; fo=1`. Review reports for 2–4 weeks, then move to "
                    "`p=quarantine` and finally `p=reject`.",
        refs=["https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure"]),
    "email_dmarc_none": dict(
        factor="email", severity="medium", title="DMARC policy is p=none (monitor only)",
        description="p=none collects reports but does not stop spoofed mail.",
        remediation="After confirming legitimate senders pass SPF/DKIM in the aggregate reports, "
                    "raise to `p=quarantine` then `p=reject`.", refs=[]),
    "email_dmarc_partial": dict(
        factor="email", severity="low", title="DMARC enforcement applies to only part of the mail (pct<100)",
        description="With pct below 100 only a fraction of failing messages is acted on.",
        remediation="Remove the pct tag (defaults to 100) once reports are clean.", refs=[]),
    "email_dmarc_no_rua": dict(
        factor="email", severity="low", title="DMARC has no aggregate report address (rua)",
        description="Without rua you get no visibility into who is sending as your domain.",
        remediation="Add `rua=mailto:dmarc-reports@<domain>` (or a free/paid DMARC report processor).",
        refs=[]),
    "email_dmarc_invalid": dict(
        factor="email", severity="medium", title="DMARC record is malformed",
        description="Receivers ignore DMARC records that don't start with v=DMARC1 and contain a valid p= tag, "
                    "or when more than one record exists.",
        remediation="Publish exactly one record: `v=DMARC1; p=quarantine; rua=mailto:...`.", refs=[]),
    "email_dmarc_weak_sp": dict(
        factor="email", severity="low", title="DMARC subdomain policy (sp) weaker than main policy",
        description="Attackers can spoof non-existent subdomains (billing.example.com) if sp=none.",
        remediation="Set `sp=reject` (or remove sp so it inherits p).", refs=[]),
    "email_dmarc_ok": dict(factor="email", severity="pass", title="DMARC enforced", description="",
                           remediation="", refs=[]),
    "email_dkim_not_found": dict(
        factor="email", severity="low", title="No DKIM key found at common selectors",
        description="DKIM selectors can't be enumerated, so this is tentative. We checked common "
                    "selectors (including Microsoft 365's selector1/selector2) and found none.",
        remediation=_M365_DKIM + " For other senders, enable DKIM in that platform and publish its key.",
        refs=["https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure"]),
    "email_dkim_weak_key": dict(
        factor="email", severity="medium", title="DKIM key shorter than 2048 bits",
        description="1024-bit RSA DKIM keys are considered weak; anything shorter is breakable.",
        remediation="Rotate to 2048-bit keys. M365: Rotate-DkimSigningConfig -KeySize 2048 -Identity <domain>",
        refs=[]),
    "email_dkim_ok": dict(factor="email", severity="pass", title="DKIM key published", description="",
                          remediation="", refs=[]),
    "email_mtasts_missing": dict(
        factor="email", severity="low", title="No MTA-STS policy",
        description="MTA-STS forces sending servers to use verified TLS when delivering to you, "
                    "preventing downgrade/man-in-the-middle on inbound mail.",
        remediation="Publish TXT `_mta-sts.<domain>` = `v=STSv1; id=20260101` and host "
                    "https://mta-sts.<domain>/.well-known/mta-sts.txt with `version: STSv1`, "
                    "`mode: enforce`, one `mx:` line per MX host (wildcards allowed), `max_age: 604800`. "
                    "Use the MX hosts listed in the evidence; for Exchange Online that's "
                    "`mx: *.mail.protection.outlook.com`. Start with `mode: testing` to confirm nothing breaks.",
        refs=["https://learn.microsoft.com/purview/enhancing-mail-flow-with-mta-sts"]),
    "email_mtasts_testing": dict(
        factor="email", severity="info", title="MTA-STS in testing mode",
        description="Policy is published but not enforced.", remediation="Switch `mode: testing` to `mode: enforce`.",
        refs=[]),
    "email_tlsrpt_missing": dict(
        factor="email", severity="low", title="No SMTP TLS reporting (TLS-RPT)",
        description="TLS-RPT sends you reports when other servers fail to deliver to you securely.",
        remediation="TXT `_smtp._tls.<domain>` = `v=TLSRPTv1; rua=mailto:tlsrpt@<domain>`.", refs=[]),
    "email_mtasts_ok": dict(factor="email", severity="pass", title="MTA-STS enforced", description="",
                            remediation="", refs=[]),

    # -------------------------------------------------------------------- DNS
    "dns_dnssec_missing": dict(
        factor="dns", severity="low", title="DNSSEC not enabled",
        description="DNSSEC signs DNS answers so resolvers can detect spoofed responses.",
        remediation="Enable DNSSEC at your DNS host (Cloudflare/Route 53/Azure DNS all support it) "
                    "and publish the DS record at your registrar.", refs=[]),
    "dns_dnssec_ok": dict(factor="dns", severity="pass", title="DNSSEC enabled", description="",
                          remediation="", refs=[]),
    "dns_caa_missing": dict(
        factor="dns", severity="low", title="No CAA record",
        description="CAA restricts which certificate authorities may issue certificates for the domain.",
        remediation="Add CAA records for the CAs you use, e.g. `0 issue \"letsencrypt.org\"`, "
                    "`0 issue \"digicert.com\"`, plus `0 iodef \"mailto:security@<domain>\"`.", refs=[]),
    "dns_caa_ok": dict(factor="dns", severity="pass", title="CAA record present", description="",
                       remediation="", refs=[]),
    "dns_ns_single": dict(
        factor="dns", severity="medium", title="Fewer than two nameservers",
        description="A single authoritative nameserver is a single point of failure.",
        remediation="Use at least two nameservers on separate networks (most DNS providers give 2–4).",
        refs=[]),
    "dns_ns_lame": dict(
        factor="dns", severity="medium", title="Lame / unresponsive nameserver delegation",
        description="A listed nameserver doesn't answer authoritatively for the zone, causing intermittent failures.",
        remediation="Remove the stale NS record at the registrar or fix the zone on that server.", refs=[]),
    "dns_axfr_allowed": dict(
        factor="dns", severity="high", title="DNS zone transfer (AXFR) allowed to anyone",
        description="Anyone can download the full zone, revealing every internal hostname.",
        remediation="Restrict AXFR to secondary nameserver IPs only (allow-transfer / Zone Transfers tab).",
        refs=[]),
    "dns_dangling_cname": dict(
        factor="dns", severity="high", title="Dangling CNAME — possible subdomain takeover",
        description="This hostname points (CNAME) at a cloud resource that no longer exists. An "
                    "attacker can often register that resource name and serve content on your subdomain.",
        remediation="Delete the CNAME record, or recreate the resource. For Azure, use "
                    "domain-verification IDs (asuid TXT) to prevent takeover.",
        refs=["https://learn.microsoft.com/azure/security/fundamentals/subdomain-takeover"]),
    "dns_dangling_cname_stale": dict(
        factor="dns", severity="low", title="Stale CNAME — target no longer exists",
        description="This hostname points (CNAME) at a name that no longer resolves. The target has a "
                    "shape the provider assigns itself (random ID, hash or extra labels), or isn't a "
                    "known cloud service, so it can't simply be re-registered. It's still a dead record: "
                    "it breaks the hostname and becomes a takeover if the target name ever becomes "
                    "available again (for example, an expired domain).",
        remediation="Delete the CNAME record (or point it at a live resource). Remove DNS records as "
                    "part of deprovisioning any cloud resource.",
        refs=["https://learn.microsoft.com/azure/security/fundamentals/subdomain-takeover"]),
    "dns_ok": dict(factor="dns", severity="pass", title="Nameservers healthy", description="",
                   remediation="", refs=[]),

    # -------------------------------------------------------------------- TLS
    "tls_no_https": dict(
        factor="tls", severity="medium", title="Website not available over HTTPS",
        description="The site serves HTTP only; traffic and credentials travel in cleartext.",
        remediation="Install a certificate (free via Let's Encrypt / your host / Cloudflare) and redirect HTTP to HTTPS.",
        refs=[]),
    "tls_cert_expired": dict(
        factor="tls", severity="high", title="TLS certificate expired",
        description="Browsers show a full-page warning; users learn to click through warnings.",
        remediation="Renew the certificate and automate renewal (ACME / certbot / host auto-renew).", refs=[]),
    "tls_cert_expiring": dict(
        factor="tls", severity="medium", title="TLS certificate expires soon",
        description="Certificate expires within 30 days (high within 7 days, medium within 14, low otherwise).",
        remediation="Renew now and put certificate expiry on monitoring.", refs=[]),
    "tls_cert_untrusted": dict(
        factor="tls", severity="high", title="TLS certificate not trusted (self-signed / incomplete chain)",
        description="The certificate does not chain to a public root, or intermediates are missing.",
        remediation="Use a publicly trusted certificate and configure the full chain "
                    "(server cert + intermediates) on the server.", refs=[]),
    "tls_cert_hostname_mismatch": dict(
        factor="tls", severity="high", title="TLS certificate does not match hostname",
        description="The certificate is valid for other names, so browsers will warn.",
        remediation="Issue a certificate whose SAN includes this hostname, or remove the DNS record if the host is unused.",
        refs=[]),
    "tls_weak_key": dict(
        factor="tls", severity="medium", title="Weak certificate key (RSA < 2048 bits)",
        description="Short RSA keys are considered breakable.", remediation="Reissue with RSA 2048+ or ECDSA P-256.",
        refs=[]),
    "tls_sha1_sig": dict(
        factor="tls", severity="medium", title="Certificate signed with SHA-1/MD5",
        description="Deprecated signature algorithm.", remediation="Reissue with SHA-256.", refs=[]),
    "tls_old_protocol": dict(
        factor="tls", severity="medium", title="Legacy TLS 1.0 / 1.1 enabled",
        description="TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail PCI DSS.",
        remediation="Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only. IIS: use IIS Crypto or the "
                    "SCHANNEL registry keys. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: "
                    "`SSLProtocol -all +TLSv1.2 +TLSv1.3`.", refs=["https://www.rfc-editor.org/rfc/rfc8996"]),
    "tls_sslv3": dict(
        factor="tls", severity="high", title="SSLv2/SSLv3 enabled",
        description="Broken protocols (POODLE, DROWN).", remediation="Disable SSLv2/SSLv3 entirely.", refs=[]),
    "tls_weak_cipher": dict(
        factor="tls", severity="medium", title="Weak cipher suites accepted",
        description="Server accepts obsolete ciphers (RC4, 3DES, NULL, EXPORT, or non-forward-secret).",
        remediation="Use the Mozilla 'intermediate' cipher configuration (ssl-config.mozilla.org).",
        refs=["https://ssl-config.mozilla.org/"]),
    "tls_no_tls13": dict(
        factor="tls", severity="info", title="TLS 1.3 not supported",
        description="Not a vulnerability, but TLS 1.3 is faster and removes legacy crypto.",
        remediation="Enable TLS 1.3 (Windows Server 2022+, OpenSSL 1.1.1+).", refs=[]),
    "tls_testssl": dict(
        factor="tls", severity="medium", title="TLS issue reported by testssl.sh",
        description="See evidence for the specific testssl.sh finding.",
        remediation="See https://testssl.sh and the Mozilla TLS guidelines for the specific item.", refs=[]),
    "tls_ok": dict(factor="tls", severity="pass", title="TLS certificate valid and trusted", description="",
                   remediation="", refs=[]),

    # ----------------------------------------------------------------- APPSEC
    "http_no_redirect": dict(
        factor="appsec", severity="medium", title="HTTP does not redirect to HTTPS",
        description="Visitors who type the bare domain get an unencrypted page.",
        remediation="Return a 301 from http:// to https:// for all paths. IIS: URL Rewrite rule; "
                    "Nginx: `return 301 https://$host$request_uri;`.", refs=[]),
    "http_hsts_missing": dict(
        factor="appsec", severity="medium", title="HSTS header missing",
        description="Without Strict-Transport-Security a network attacker can downgrade users to HTTP (SSL stripping).",
        remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.",
        refs=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]),
    "http_hsts_short": dict(
        factor="appsec", severity="low", title="HSTS max-age shorter than 180 days",
        description="Short HSTS lifetimes give weak protection.", remediation="Use max-age=31536000 (1 year).",
        refs=[]),
    "http_csp_missing": dict(
        factor="appsec", severity="low", title="Content-Security-Policy header missing",
        description="CSP limits where scripts can load from and is the main browser-side defense against XSS.",
        remediation="Start with `Content-Security-Policy-Report-Only` to learn, then enforce. Minimum "
                    "useful: `default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'`.",
        refs=["https://developer.mozilla.org/docs/Web/HTTP/CSP"]),
    "http_xfo_missing": dict(
        factor="appsec", severity="low", title="Clickjacking protection missing",
        description="Neither X-Frame-Options nor CSP frame-ancestors is set, so the site can be framed.",
        remediation="Add `X-Frame-Options: SAMEORIGIN` or CSP `frame-ancestors 'self'`.", refs=[]),
    "http_xcto_missing": dict(
        factor="appsec", severity="low", title="X-Content-Type-Options header missing",
        description="Browsers may MIME-sniff responses into executable types.",
        remediation="Add `X-Content-Type-Options: nosniff`.", refs=[]),
    "http_referrer_missing": dict(
        factor="appsec", severity="info", title="Referrer-Policy header missing",
        description="Full URLs (possibly with tokens) may leak to third parties via Referer.",
        remediation="Add `Referrer-Policy: strict-origin-when-cross-origin`.", refs=[]),
    "http_cookie_insecure": dict(
        factor="appsec", severity="medium", title="Cookie set without Secure flag",
        description="Cookie can be sent over plain HTTP and intercepted.",
        remediation="Set the Secure attribute on all cookies served over HTTPS.", refs=[]),
    "http_cookie_httponly": dict(
        factor="appsec", severity="low", title="Session-like cookie without HttpOnly",
        description="JavaScript (and therefore XSS) can read the cookie.",
        remediation="Set HttpOnly on session/auth cookies.", refs=[]),
    "http_cookie_samesite": dict(
        factor="appsec", severity="info", title="Cookie without SameSite attribute",
        description="Browsers default to Lax, but explicit SameSite hardens against CSRF.",
        remediation="Set `SameSite=Lax` (or Strict) explicitly.", refs=[]),
    "http_mixed_content": dict(
        factor="appsec", severity="low", title="Mixed content on HTTPS page",
        description="HTTPS page loads scripts/styles over HTTP, which can be tampered with.",
        remediation="Load all resources over https:// (or protocol-relative / same-origin).", refs=[]),
    "http_cors_reflect": dict(
        factor="appsec", severity="high", title="CORS reflects arbitrary Origin with credentials",
        description="Any website can make authenticated requests and read responses on behalf of logged-in users.",
        remediation="Only echo origins from an allow-list; never combine a reflected origin with "
                    "Access-Control-Allow-Credentials: true.", refs=[]),
    "http_cors_wildcard": dict(
        factor="appsec", severity="info", title="CORS allows any origin (*)",
        description="Fine for truly public content; a problem if responses contain private data.",
        remediation="Restrict Access-Control-Allow-Origin to the origins that need it.", refs=[]),
    "http_dir_listing": dict(
        factor="exposure", severity="medium", title="Directory listing enabled",
        description="Web server lists directory contents, exposing files not meant to be linked.",
        remediation="Disable autoindex (Nginx `autoindex off;`, Apache `Options -Indexes`, IIS Directory Browsing off).",
        refs=[]),
    "http_security_txt_missing": dict(
        factor="appsec", severity="info", title="No security.txt",
        description="security.txt tells researchers how to report vulnerabilities to you.",
        remediation="Publish /.well-known/security.txt with Contact: and Expires: fields (securitytxt.org).",
        refs=["https://securitytxt.org/"]),
    "http_headers_ok": dict(factor="appsec", severity="pass", title="Core security headers present",
                            description="", remediation="", refs=[]),
    "nuclei_finding": dict(
        factor="appsec", severity="medium", title="Nuclei template match",
        description="See evidence for template details.",
        remediation="See the template references in the evidence.", refs=[]),

    # --------------------------------------------------------------- PATCHING
    "sw_eol": dict(
        factor="patching", severity="high", title="End-of-life software detected",
        description="This product version no longer receives security updates from the vendor.",
        remediation="Upgrade to a supported release. If the banner is wrong (e.g. backported OS "
                    "packages), suppress the version banner so scanners stop flagging it.",
        refs=["https://endoflife.date/"]),
    "sw_outdated": dict(
        factor="patching", severity="medium", title="Software not on latest patch release",
        description="A newer patch release exists in this supported branch.",
        remediation="Apply the latest vendor patch for this branch.", refs=[]),
    "sw_supported": dict(factor="patching", severity="pass", title="Detected software is supported",
                         description="", remediation="", refs=[]),
    "vuln_kev": dict(
        factor="patching", severity="critical", title="Known Exploited Vulnerability (CISA KEV)",
        description="This CVE is actively exploited in the wild and is on CISA's KEV catalog. "
                    "Detection is version-based, so verify, but treat as urgent.",
        remediation="Patch immediately per the vendor advisory; if you can't, remove internet exposure "
                    "and hunt for signs of compromise.",
        refs=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]),
    "vuln_high_epss": dict(
        factor="patching", severity="high", title="Vulnerability with high exploit probability (EPSS)",
        description="FIRST EPSS estimates a high probability this CVE is exploited in the next 30 days.",
        remediation="Prioritise patching; verify version and apply vendor fix.", refs=["https://www.first.org/epss/"]),
    "vuln_cve": dict(
        factor="patching", severity="medium", title="Potential CVE based on detected version",
        description="Version-based match from Shodan InternetDB/nuclei; not exploit-verified.",
        remediation="Confirm the installed version and apply vendor patches.", refs=[]),
    "edge_appliance_exposed": dict(
        factor="patching", severity="medium", title="Remote-access/VPN appliance exposed",
        description="VPN and gateway appliances (Fortinet, Ivanti/Pulse, Citrix, Palo Alto, SonicWall) "
                    "are the #1 initial-access vector for ransomware. Exposure is expected, but they "
                    "must be patched within days of advisories.",
        remediation="Confirm firmware is current, subscribe to the vendor PSIRT feed, require MFA, "
                    "and check CISA KEV for this product.", refs=[]),
    "exchange_onprem_exposed": dict(
        factor="patching", severity="medium", title="On-premises Exchange (OWA/ECP) exposed",
        description="On-prem Exchange has repeatedly been mass-exploited (ProxyLogon, ProxyShell). "
                    "The build number below can be checked against Microsoft's build list.",
        remediation="Apply the latest Exchange CU + SU, restrict /ecp to internal networks, or "
                    "decommission if mailboxes are already in Exchange Online.",
        refs=["https://learn.microsoft.com/exchange/new-features/build-numbers-and-release-dates"]),

    # ---------------------------------------------------------------- NETWORK
    "net_exposed_rdp": dict(
        factor="network", severity="high", title="RDP exposed to the internet",
        description="Internet-facing RDP is brute-forced constantly and is a leading ransomware entry point.",
        remediation="Close 3389 at the firewall. Use a VPN with MFA, Azure Bastion, Entra ID App "
                    "Proxy / RD Gateway with MFA instead.", refs=[]),
    "net_exposed_smb": dict(
        factor="network", severity="critical", title="SMB / NetBIOS / RPC exposed",
        description="SMB (445/139) and RPC (135) should never be internet-reachable (EternalBlue, relay attacks).",
        remediation="Block TCP 135/137-139/445 inbound at the perimeter.", refs=[]),
    "net_exposed_telnet": dict(
        factor="network", severity="high", title="Telnet exposed",
        description="Cleartext remote login, frequently with default credentials on network gear.",
        remediation="Disable Telnet; use SSH restricted by source IP.", refs=[]),
    "net_exposed_ftp": dict(
        factor="network", severity="medium", title="FTP exposed",
        description="FTP sends credentials in cleartext.", remediation="Replace with SFTP/FTPS or a file-sharing service.",
        refs=[]),
    "net_exposed_db": dict(
        factor="network", severity="high", title="Database port exposed",
        description="SQL Server, MySQL, PostgreSQL or Oracle reachable from the internet.",
        remediation="Bind to private interfaces / firewall to application servers only; never expose DBs publicly.",
        refs=[]),
    "net_exposed_datastore": dict(
        factor="network", severity="critical", title="Unauthenticated-by-default datastore exposed",
        description="Redis, MongoDB, Elasticsearch, Memcached, CouchDB etc. are routinely wiped/ransomed when exposed.",
        remediation="Firewall immediately, enable authentication, bind to localhost/private IPs.", refs=[]),
    "net_exposed_docker": dict(
        factor="network", severity="critical", title="Docker / Kubernetes API exposed",
        description="An exposed container API usually means full host compromise.",
        remediation="Firewall the port; require TLS client auth; never expose 2375.", refs=[]),
    "net_exposed_remote_admin": dict(
        factor="network", severity="high", title="Remote administration service exposed",
        description="VNC, WinRM, Webmin, SNMP or similar admin interfaces reachable from the internet.",
        remediation="Restrict to VPN / management network; require MFA.", refs=[]),
    "net_exposed_ldap": dict(
        factor="network", severity="high", title="LDAP / Active Directory service exposed",
        description="Domain controllers or LDAP directories should not be internet-reachable.",
        remediation="Block 389/636/3268/88 inbound; use Entra ID for external auth.", refs=[]),
    "net_exposed_cleartext_mail": dict(
        factor="network", severity="low", title="Cleartext mail protocol exposed (POP3/IMAP)",
        description="POP3/IMAP without TLS exposes credentials.",
        remediation="Disable 110/143; use 995/993 only, or disable legacy protocols entirely (M365: "
                    "turn off POP/IMAP per mailbox and block legacy auth via Conditional Access).",
        refs=[]),
    "net_exposed_ssh": dict(
        factor="network", severity="info", title="SSH exposed",
        description="Generally acceptable if key-only auth and patched, but reduces attack surface to restrict it.",
        remediation="Disable password auth, restrict source IPs, keep OpenSSH patched.", refs=[]),
    "net_exposed_other": dict(
        factor="network", severity="info", title="Additional open port",
        description="Open port not in the high-risk list; confirm it is intentional.",
        remediation="Close any service that doesn't need to be internet-facing.", refs=[]),
    "net_exposed_admin_web": dict(
        factor="network", severity="medium", title="Management web interface exposed",
        description="Firewall/router/hypervisor management UI (e.g. 8443/10443/4443, Webmin, Kibana) reachable publicly.",
        remediation="Move management interfaces to an internal VLAN or restrict by source IP.", refs=[]),

    # ------------------------------------------------------------- REPUTATION
    "rep_dnsbl_listed": dict(
        factor="reputation", severity="high", title="IP listed on a spam/abuse blocklist",
        description="Blocklisted IPs often indicate a compromised host, open relay, or infected device sending spam.",
        remediation="Identify what on that IP is sending mail/traffic, clean it, then request delisting "
                    "via the blocklist's lookup page.", refs=["https://check.spamhaus.org/"]),
    "rep_domain_blocklisted": dict(
        factor="reputation", severity="high", title="Domain on a blocklist",
        description="The domain appears on a domain blocklist (malware/phishing/spam).",
        remediation="Check for compromised web content or abused redirects, clean up, then request removal.",
        refs=[]),
    "rep_abuseipdb": dict(
        factor="reputation", severity="medium", title="IP reported for abuse (AbuseIPDB)",
        description="Other organizations have reported malicious traffic from this IP.",
        remediation="Investigate the host for compromise (malware, brute-forcing outbound, proxies). "
                    "Shared/cloud IPs may carry reports from previous tenants; if so, request delisting with the reporting service.",
        refs=["https://www.abuseipdb.com/"]),
    "rep_greynoise_malicious": dict(
        factor="reputation", severity="high", title="IP observed scanning/attacking the internet (GreyNoise)",
        description="GreyNoise sensors saw this IP performing malicious internet-wide activity — usually a compromised host.",
        remediation="Treat as an incident: isolate the host behind that IP and investigate.",
        refs=["https://viz.greynoise.io/"]),
    "rep_shodan_tag": dict(
        factor="reputation", severity="high", title="Shodan tags this IP as compromised/malware",
        description="Shodan has tagged the host (e.g. 'compromised', 'malware', 'c2', 'doublepulsar').",
        remediation="Treat as an incident and investigate the host.", refs=[]),
    "rep_clean": dict(factor="reputation", severity="pass", title="No reputation issues found",
                      description="", remediation="", refs=[]),

    # --------------------------------------------------------------- EXPOSURE
    "exp_git": dict(factor="exposure", severity="critical", title="Exposed .git repository",
                    description="Source code and history (often including secrets) can be downloaded.",
                    remediation="Block access to /.git/ at the web server and rotate any secrets in the repo history.",
                    refs=[]),
    "exp_svn": dict(factor="exposure", severity="medium", title="Exposed .svn metadata",
                    description="Subversion metadata reveals source files.",
                    remediation="Block /.svn/ and remove it from the web root.", refs=[]),
    "exp_env": dict(factor="exposure", severity="critical", title="Exposed .env file with secrets",
                    description="Environment file containing credentials/API keys is publicly readable.",
                    remediation="Remove from web root, block dotfiles, and rotate every secret in it NOW.", refs=[]),
    "exp_config_backup": dict(factor="exposure", severity="critical", title="Exposed configuration/backup file",
                              description="Configuration file (wp-config, web.config, etc.) readable, likely with credentials.",
                              remediation="Delete the file from the web root and rotate credentials.", refs=[]),
    "exp_aws_creds": dict(factor="exposure", severity="critical", title="Exposed cloud credentials file",
                          description="AWS credentials readable over HTTP.",
                          remediation="Deactivate the keys in IAM immediately, then remove the file.", refs=[]),
    "exp_backup_archive": dict(factor="exposure", severity="high", title="Downloadable backup archive / SQL dump",
                               description="Backup archives or database dumps in the web root.",
                               remediation="Remove from the web root; store backups outside public paths.", refs=[]),
    "exp_actuator": dict(factor="exposure", severity="high", title="Spring Boot Actuator endpoint exposed",
                         description="/actuator/env etc. leaks configuration and sometimes allows RCE.",
                         remediation="Set management.endpoints.web.exposure.include=health and secure the rest.",
                         refs=[]),
    "exp_server_status": dict(factor="exposure", severity="medium", title="Apache server-status exposed",
                              description="Reveals client IPs, URLs being requested and internal vhosts.",
                              remediation="Restrict /server-status to localhost (`Require local`).", refs=[]),
    "exp_phpinfo": dict(factor="exposure", severity="medium", title="phpinfo() page exposed",
                        description="Reveals PHP/OS versions, paths, environment variables.",
                        remediation="Delete phpinfo/info.php from the server.", refs=[]),
    "exp_ds_store": dict(factor="exposure", severity="low", title="Exposed .DS_Store",
                         description="macOS metadata file lists directory contents.",
                         remediation="Delete .DS_Store files and block dotfiles.", refs=[]),
    "exp_debug_handler": dict(factor="exposure", severity="medium", title="ASP.NET debug handler exposed",
                              description="elmah.axd / trace.axd reveal errors, requests, and sometimes session cookies.",
                              remediation="Remove the handler or restrict to localhost in web.config.", refs=[]),
    "exp_admin_panel": dict(factor="exposure", severity="medium", title="Admin panel publicly reachable",
                            description="Database/admin UI (e.g. phpMyAdmin) reachable from the internet.",
                            remediation="Restrict by IP / VPN, or remove.", refs=[]),
    "exp_wp_user_enum": dict(factor="exposure", severity="low", title="WordPress user enumeration via REST API",
                             description="Usernames are listed at /wp-json/wp/v2/users, aiding password attacks.",
                             remediation="Restrict the users endpoint (security plugin or a small mu-plugin).", refs=[]),
    "exp_xmlrpc": dict(factor="exposure", severity="low", title="WordPress xmlrpc.php enabled",
                       description="Used for credential brute-force amplification and pingback DDoS.",
                       remediation="Disable XML-RPC unless Jetpack/mobile app needs it.", refs=[]),
    "exp_crossdomain": dict(factor="exposure", severity="low", title="Permissive crossdomain.xml",
                            description="Allows any domain (`*`) to make cross-domain Flash/Silverlight requests.",
                            remediation="Remove the file or restrict domains.", refs=[]),
    "exp_api_docs": dict(factor="exposure", severity="info", title="API documentation publicly accessible",
                         description="Swagger/OpenAPI docs map the attack surface; fine if intended.",
                         remediation="Restrict if the API is not meant to be public.", refs=[]),
    "exp_version_disclosure": dict(
        factor="exposure", severity="low", title="Software version disclosed in banner/header",
        description="Exact version numbers let attackers and automated scanners match you to CVEs instantly.",
        remediation="IIS: remove Server header (`removeServerHeader=\"true\"` in requestFiltering) and "
                    "X-Powered-By / X-AspNet-Version. Nginx: `server_tokens off;`. Apache: "
                    "`ServerTokens Prod` + `ServerSignature Off`. PHP: `expose_php = Off`.", refs=[]),
    "leak_breached_accounts": dict(
        factor="exposure", severity="medium", title="Accounts found in public breaches (HIBP)",
        description="Email addresses on this domain appear in known data breaches; reused passwords "
                    "enable credential stuffing.",
        remediation="Force password resets for affected users, enforce MFA (Entra Conditional Access), "
                    "and enable Entra ID Password Protection / leaked-credential detection.",
        refs=["https://haveibeenpwned.com/DomainSearch"]),
}


def get(check_id: str) -> dict:
    base = CHECKS.get(check_id) or dict(factor="appsec", severity="info", title=check_id,
                                         description="", remediation="", refs=[])
    return {**base, "verify": VERIFY.get(check_id, "")}


# ---------------------------------------------------------------------------------------
# How to manually verify each finding (false-positive triage). {asset} and {domain} are
# substituted in the report. Commands work on Linux; most also work in PowerShell
# with curl.exe / nslookup / Test-NetConnection as noted.
# ---------------------------------------------------------------------------------------
VERIFY: dict[str, str] = {
    # email
    "email_spf_missing": "`dig +short TXT {domain}` (Windows: `nslookup -type=txt {domain}`) — look for a line starting v=spf1. Query an authoritative NS (`dig @ns1.provider TXT {domain}`) to rule out resolver caching.",
    "email_spf_multiple": "`dig +short TXT {domain} | grep -i spf1` — more than one line = permerror.",
    "email_spf_permissive": "`dig +short TXT {domain}` — check the final `all` qualifier.",
    "email_spf_softfail": "`dig +short TXT {domain}` — record ends in `~all`.",
    "email_spf_too_many_lookups": "Paste the domain into an SPF lookup counter (e.g. MXToolbox SPF, dmarcian SPF surveyor) — it should report >10 lookups.",
    "email_spf_ptr": "`dig +short TXT {domain}` — look for a `ptr` mechanism.",
    "email_dmarc_missing": "`dig +short TXT _dmarc.{domain}` (Windows: `nslookup -type=txt _dmarc.{domain}`).",
    "email_dmarc_none": "`dig +short TXT _dmarc.{domain}` — shows p=none.",
    "email_dmarc_partial": "`dig +short TXT _dmarc.{domain}` — shows pct below 100.",
    "email_dmarc_no_rua": "`dig +short TXT _dmarc.{domain}` — no rua= tag.",
    "email_dmarc_invalid": "`dig +short TXT _dmarc.{domain}` — check for multiple records or a missing/invalid p= tag.",
    "email_dmarc_weak_sp": "`dig +short TXT _dmarc.{domain}` — compare sp= to p=.",
    "email_dkim_not_found": "LIKELY FALSE POSITIVE if the org uses a custom selector. Open the headers of any email sent from {domain} and read `DKIM-Signature: ... s=<selector>`; then `dig +short TXT <selector>._domainkey.{domain}`. Re-run with `--dkim-selectors <selector>`.",
    "email_dkim_weak_key": "`dig +short TXT <selector>._domainkey.{domain}` and decode the p= key length (`echo <p> | base64 -d | openssl rsa -pubin -inform DER -text -noout | head -1`).",
    "email_mtasts_missing": "`dig +short TXT _mta-sts.{domain}` and `curl https://mta-sts.{domain}/.well-known/mta-sts.txt`.",
    "email_tlsrpt_missing": "`dig +short TXT _smtp._tls.{domain}`.",
    "email_mtasts_testing": "`curl https://mta-sts.{domain}/.well-known/mta-sts.txt` — shows mode: testing.",
    # dns
    "dns_dnssec_missing": "`dig +short DS {domain}` (empty = unsigned) or use dnsviz.net.",
    "dns_caa_missing": "`dig +short CAA {domain}`.",
    "dns_ns_single": "`dig +short NS {domain}`.",
    "dns_ns_lame": "`dig @<nameserver> SOA {domain}` for each NS — look for the `aa` flag in the response.",
    "dns_axfr_allowed": "`dig AXFR {domain} @<nameserver>` returns the full zone.",
    "dns_dangling_cname": "`dig +short CNAME {asset}` then `dig +short A <target>` → NXDOMAIN confirms. Also browse to {asset}: providers show a 'not found / no such app' page. Do NOT attempt to claim the resource yourself. Azure Traffic Manager: `az network traffic-manager profile check-dns --name <name>` is a read-only availability check (nameAvailable: true = claimable).",
    "dns_dangling_cname_stale": "`dig +short CNAME {asset}` then `dig A <target>` → status NXDOMAIN confirms the record is dead. For a target outside a cloud provider, `whois <target's registered domain>` shows whether that domain has expired (if it has, treat this as a takeover risk).",
    # tls
    "tls_no_https": "`curl -vI https://{asset}` — connection refused/timeout confirms.",
    "tls_cert_expired": "`echo | openssl s_client -connect {asset}:443 -servername {asset} 2>/dev/null | openssl x509 -noout -dates`.",
    "tls_cert_expiring": "`echo | openssl s_client -connect {asset}:443 -servername {asset} 2>/dev/null | openssl x509 -noout -enddate`.",
    "tls_cert_untrusted": "`curl -vI https://{asset}` — 'unable to get local issuer' = missing intermediate; also SSL Labs. Note: corporate TLS-inspection proxies on YOUR side can cause this — re-test from another network.",
    "tls_cert_hostname_mismatch": "`echo | openssl s_client -connect {asset}:443 -servername {asset} 2>/dev/null | openssl x509 -noout -ext subjectAltName`.",
    "tls_weak_key": "`echo | openssl s_client -connect {asset}:443 -servername {asset} 2>/dev/null | openssl x509 -noout -text | grep 'Public-Key'`.",
    "tls_sha1_sig": "`... | openssl x509 -noout -text | grep 'Signature Algorithm'`.",
    "tls_old_protocol": "`openssl s_client -connect {asset}:443 -tls1_1` (or `nmap --script ssl-enum-ciphers -p 443 {asset}`). Note: on OpenSSL 3 add `-cipher 'DEFAULT:@SECLEVEL=0'` or the local client refuses first.",
    "tls_weak_cipher": "`nmap --script ssl-enum-ciphers -p 443 {asset}` — look for grades below A, or run testssl.sh.",
    "tls_testssl": "`testssl.sh {asset}` and read the matching item.",
    "tls_sslv3": "`nmap --script ssl-enum-ciphers -p 443 {asset}` or `testssl.sh -p {asset}`.",
    "tls_no_tls13": "`openssl s_client -connect {asset}:443 -tls1_3`.",
    # appsec
    "http_no_redirect": "`curl -sI {url}` — expect `301/308` with `Location: https://...`.",
    "http_hsts_missing": "`curl -sI {url} | grep -i strict-transport` (PowerShell: `curl.exe -sI https://{asset}`). If the site sits behind a CDN/WAF, check the CDN's HSTS setting too.",
    "http_hsts_short": "`curl -sI {url} | grep -i strict-transport` — check max-age.",
    "http_csp_missing": "`curl -sI {url} | grep -i content-security`. Some apps set CSP only via <meta> tag — check page source; meta CSP still counts for XSS but not for frame-ancestors.",
    "http_xfo_missing": "`curl -sI {url} | grep -iE 'x-frame|frame-ancestors'`.",
    "http_xcto_missing": "`curl -sI {url} | grep -i x-content-type`.",
    "http_referrer_missing": "`curl -sI {url} | grep -i referrer-policy`.",
    "http_cookie_insecure": "`curl -sI {url} | grep -i set-cookie` — check for `Secure`. Load-balancer stickiness cookies are common, low-impact offenders.",
    "http_cookie_httponly": "`curl -sI {url} | grep -i set-cookie` — check for `HttpOnly`. Cookies that front-end JS must read (e.g. CSRF tokens) legitimately omit it → mark false positive.",
    "http_cookie_samesite": "`curl -sI {url} | grep -i set-cookie`.",
    "http_mixed_content": "Open https://{asset} in a browser → DevTools Console shows 'Mixed Content' warnings.",
    "http_cors_reflect": "`curl -sI -H 'Origin: https://evil.example' {url}` — both `Access-Control-Allow-Origin: https://evil.example` and `Access-Control-Allow-Credentials: true` confirm. Only exploitable if the endpoint returns user-specific data.",
    "http_cors_wildcard": "`curl -sI -H 'Origin: https://x.example' https://{asset}`.",
    "http_dir_listing": "Open the URL in the evidence — an 'Index of /' page confirms.",
    "http_security_txt_missing": "`curl -s https://{domain}/.well-known/security.txt`.",
    # patching
    "sw_eol": "Check the banner: `curl -sI {url} | grep -iE 'server|x-powered'`. COMMON FALSE POSITIVE: Linux distros (RHEL, Ubuntu, Debian) backport security fixes without changing the version string — check the OS release with the server owner (`apache2 -v`, `rpm -q httpd`, `dpkg -l | grep apache2`).",
    "sw_outdated": "Same as above — on distro packages, compare against the distro's security tracker (ubuntu.com/security, access.redhat.com), not upstream.",
    "vuln_kev": "Version-based match. Confirm the installed version/build on the device itself and compare to the vendor advisory's fixed version. Treat as urgent until disproven.",
    "vuln_high_epss": "Version-based match. Confirm installed version against the CVE's affected range on nvd.nist.gov.",
    "vuln_cve": "Version-based match from Shodan's fingerprint (may be days–weeks old). Confirm installed version and whether the vulnerable component/feature is enabled.",
    "edge_appliance_exposed": "Browse to the URL in the evidence. Then log in to the appliance and compare firmware to the vendor PSIRT / CISA KEV entries.",
    "exchange_onprem_exposed": "`curl -sI https://{asset}/owa/auth/logon.aspx | grep -i x-owa-version`, then look the build up in Microsoft's Exchange build numbers table.",
    # network
    "net_exposed_rdp": "`nmap -Pn -p 3389 {asset}` (PowerShell: `Test-NetConnection {asset} -Port 3389`). If the finding came only from Shodan and your live scan shows closed, the data is stale.",
    "net_exposed_smb": "`nmap -Pn -p 135,139,445 {asset}`. 'filtered' is NOT open. Many ISPs block 445 outbound — test from a cloud VM if your network blocks it.",
    "net_exposed_telnet": "`nmap -Pn -sV -p 23 {asset}`.",
    "net_exposed_ftp": "`nmap -Pn -sV -p 21 {asset}`.",
    "net_exposed_db": "`nmap -Pn -sV -p <port> {asset}`.",
    "net_exposed_datastore": "`nmap -Pn -sV -p <port> {asset}`. For Redis: `redis-cli -h {asset} ping` returning PONG = no auth (only do this with authorization).",
    "net_exposed_docker": "`nmap -Pn -sV -p <port> {asset}`.",
    "net_exposed_remote_admin": "`nmap -Pn -sV -p <port> {asset}`.",
    "net_exposed_ldap": "`nmap -Pn -sV -p 389,636,3268,88 {asset}`.",
    "net_exposed_cleartext_mail": "`nmap -Pn -sV -p 110,143 {asset}`.",
    "net_exposed_ssh": "`nmap -Pn -sV -p 22 {asset}`.",
    "net_exposed_admin_web": "Browse to https://{asset}:<port> — identify what the login page is.",
    "net_exposed_other": "`nmap -Pn -sV -p <port> {asset}`.",
    # reputation
    "rep_dnsbl_listed": "Look the IP up at check.spamhaus.org / mxtoolbox.com/blacklists. If the IP is shared hosting/cloud, the listing may belong to a previous or neighboring tenant.",
    "rep_domain_blocklisted": "Check the domain at check.spamhaus.org and surbl.org/surbl-analysis.",
    "rep_abuseipdb": "Open https://www.abuseipdb.com/check/{asset} — read the report categories and dates. Old reports on a recently-acquired cloud IP are a false positive for the current owner.",
    "rep_greynoise_malicious": "Open https://viz.greynoise.io/ip/{asset}.",
    "rep_shodan_tag": "Open https://www.shodan.io/host/{asset}.",
    # exposure
    "exp_git": "`curl -s {url}` returns `ref: refs/heads/...`.",
    "exp_svn": "`curl -s {url}`.",
    "exp_env": "`curl -s {url} | head -3` — confirm it contains real KEY=value lines (don't store the output).",
    "exp_config_backup": "Request the URL in the evidence and confirm it contains configuration, not a 'not found' page.",
    "exp_aws_creds": "Request the URL in the evidence; confirm `aws_access_key_id`.",
    "exp_backup_archive": "`curl -sI <url>` — Content-Length and Content-Type (application/zip, application/sql) confirm.",
    "exp_actuator": "`curl -s {url} | head -c 300`.",
    "exp_server_status": "Browse to {url}.",
    "exp_phpinfo": "Browse to the URL in the evidence.",
    "exp_ds_store": "`curl -s {url} | xxd | head -1` shows `Bud1`.",
    "exp_debug_handler": "Browse to the URL in the evidence.",
    "exp_admin_panel": "Browse to the URL in the evidence — confirm it's a real login page and not a honeypot/WAF block page.",
    "exp_wp_user_enum": "`curl -s {url}` lists usernames.",
    "exp_xmlrpc": "`curl -s {url}`.",
    "exp_crossdomain": "`curl -s {url}`.",
    "exp_api_docs": "Browse to the URL in the evidence; decide whether the API is meant to be public.",
    "exp_version_disclosure": "`curl -sI {url} | grep -iE 'server|x-powered|x-aspnet'`.",
    "leak_breached_accounts": "Review the HIBP domain dashboard. Old breaches of since-departed users are lower risk; check whether affected users still exist in Entra ID.",
    "nuclei_finding": "Re-run the single template: `nuclei -u https://{asset} -id {template} -debug` and inspect the matched request/response.",
}
