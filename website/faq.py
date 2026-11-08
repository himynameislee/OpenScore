"""OpenScore FAQ: the single source for docs/faq.md, the website's FAQ page and its schema.

Edit the questions here, then run `python3 website/build.py --faq-md` (tests fail if docs/faq.md
is out of date). Each answer is (question, lead, more): the lead answers directly and names
OpenScore so it can be quoted on its own; `more` adds detail. Markdown is limited to `code` and
[links](url), so the plain-text schema version stays faithful to the visible text.
"""

REPO = "https://github.com/himynameislee/OpenScore"
DOCS = REPO + "/blob/main/docs/"

FAQ = [
  ("About OpenScore", [
    ("What is OpenScore?",
     "OpenScore is a free, open-source external security rating tool. It looks at an organization "
     "from the outside, the way an attacker would, and grades its domain from A to F across eight "
     "security factors.",
     "Every finding in the report comes with the evidence that triggered it, a command to verify it "
     "by hand, and steps to fix it. OpenScore runs from the command line on Linux and Windows and "
     "produces a self-contained HTML report plus JSON."),
    ("Is OpenScore free?",
     "Yes. OpenScore is free and open source under the MIT license, with no account, subscription "
     "or usage limit.",
     "It runs on your own computer. A few optional data sources need an API key: AbuseIPDB and "
     "GreyNoise have free keys, and Have I Been Pwned breach data needs a paid key. OpenScore works "
     "without any of them."),
    ("Who is OpenScore for?",
     "OpenScore is for defenders and IT teams, vulnerability management, and penetration testers "
     "who need an outside-in view of an organization's attack surface.",
     "Defenders use it to see and track their own external exposure. Vulnerability management teams "
     "use rescans as a repeatable baseline. Penetration testers use it for the external "
     "attack-surface review of an authorized engagement, with evidence exhibits and an audit log "
     "for the report. It's built to be useful to small organizations that can't pay for a "
     "commercial rating subscription."),
    ("Is OpenScore an alternative to paid security rating services?",
     "OpenScore gives you a free, outside-in security rating with a fully published methodology, "
     "so you can find and fix what outsiders see without a subscription.",
     "Its score is its own: it isn't designed to reproduce any vendor's number, and grades from "
     "different tools aren't directly comparable. What OpenScore adds is transparency: every "
     "deduction is explained, every finding has a verify command, and false positives can be "
     "triaged and recorded."),
    ("Is OpenScore related to the OpenScore sheet music project?",
     "No. OpenScore the security rating tool is unrelated to the OpenScore project that digitizes "
     "public-domain sheet music.",
     "The security tool lives at " + REPO + "."),
  ]),
  ("How it works", [
    ("What does OpenScore check?",
     "OpenScore checks eight factors: email security, DNS health, TLS and certificates, application "
     "security, network exposure, patching cadence, IP and domain reputation, and information "
     "exposure.",
     "That covers SPF, DKIM, DMARC and MTA-STS; DNSSEC, CAA and subdomain takeover; certificate and "
     "protocol problems; HTTP security headers, cookies and CORS; exposed RDP, SMB, databases and "
     "admin interfaces; end-of-life software and known-exploited CVEs (CISA KEV, FIRST EPSS); "
     "blocklist listings; and leaked files such as `.git` and `.env`. The "
     "[check catalog](" + DOCS + "check-catalog.md) lists every check."),
    ("How does OpenScore calculate its security score?",
     "Each of the eight factors starts at 100 and loses points for each finding by severity: 35 for "
     "critical, 18 for high, 8 for medium and 3 for low. The overall score is a weighted average of "
     "the factors that were assessed.",
     "The same issue on more hosts counts half for each extra host, and findings that still need "
     "verification count half. A confirmed critical finding caps the overall grade at C (79). "
     "Grades are A for 90 and above, B for 80, C for 70, D for 60, and F below 60. The full method "
     "is in the [scoring documentation](" + DOCS + "scoring.md)."),
    ("What is the difference between passive, light and active scans?",
     "A passive scan uses only public data and never contacts the target; a light scan adds the "
     "requests a normal website visitor would make; an active scan adds port scans, path probes, "
     "nuclei and testssl.sh, and needs written authorization.",
     "Passive and light run by default. Active checks run only with `--active`, an "
     "`--authorization` reference and a typed scope confirmation, and every action is written to an "
     "audit log. See [modes, scope and authorization](" + DOCS + "modes-and-scope.md)."),
    ("Does OpenScore exploit vulnerabilities?",
     "No. OpenScore finds and documents issues but never exploits them: there is no exploitation, "
     "credential guessing, payload injection or form submission.",
     "nuclei runs only safe template tags (exposure, misconfiguration, TLS, takeover, panels and CVE "
     "detection), with intrusive, brute-force and denial-of-service templates excluded. "
     "Version-based CVE matches are marked tentative because OpenScore never exploits a system to "
     "confirm them."),
    ("How long does an OpenScore scan take?",
     "A passive and light scan usually takes a few minutes. A full active scan of about 60 assets "
     "takes around 50 minutes, and about half that without nuclei.",
     "Most active-scan time goes to nuclei (roughly a minute per website at the default rate) and "
     "testssl.sh (30 seconds to 2 minutes per HTTPS host). The "
     "[performance guide](" + DOCS + "performance.md) explains the speed options."),
  ]),
  ("Using OpenScore safely", [
    ("Do I need permission to scan a domain with OpenScore?",
     "You need written permission from the owner before running OpenScore's active checks. Passive "
     "and light scans only use public data and normal-visitor requests.",
     "Laws and contracts differ, so when in doubt, get permission first. OpenScore enforces this for "
     "active checks: it asks for an authorization reference and a typed scope confirmation, stays "
     "within the domain and the IPs you supply, and logs every action."),
    ("Is OpenScore safe to run against production systems?",
     "OpenScore is designed for production use: its path probes are single GET requests, its tools "
     "are rate-limited, and it never port-scans CDN or SaaS infrastructure unless you ask.",
     "Active scans pause between requests to the same host, nuclei runs at a capped request rate "
     "with safe templates only, and testssl.sh tests one host at a time. Agree a scan window with "
     "the system owner, as with any authorized test."),
    ("Does OpenScore send my scan results anywhere?",
     "No. OpenScore has no telemetry, and reports are written only to your own computer.",
     "To gather data, OpenScore queries public services such as certificate transparency logs, DNS "
     "blocklists, Shodan InternetDB, CISA KEV and FIRST EPSS, and these receive only the domain, "
     "hostnames or IP addresses being assessed. The full list is in "
     "[data sources](" + DOCS + "data-sources.md)."),
  ]),
  ("Installing and running", [
    ("How do I install OpenScore?",
     "Clone the repository and run the installer for your platform, or download a standalone "
     "binary from the GitHub releases page.",
     "On Linux: `git clone " + REPO + ".git openscore && cd openscore && ./install_linux.sh`. On "
     "Windows 10 or 11, run `install_windows.ps1` from the clone. The standalone binaries need no "
     "Python, and each release includes a checksum file and a sample report. See "
     "[getting started](" + DOCS + "getting-started.md)."),
    ("What operating systems does OpenScore support?",
     "OpenScore runs on Linux and Windows, with Python 3.11 or later or as a standalone binary.",
     "Every change is tested on Linux and Windows. The repository includes Debian packaging, so you "
     "can build a `.deb` for Debian-based distributions."),
    ("Which tools does OpenScore use?",
     "OpenScore works on its own, and uses nmap, nuclei, testssl.sh, subfinder and Playwright when "
     "they're installed.",
     "Without them, OpenScore falls back to its built-in checks: its own TCP port check and TLS "
     "checks, and certificate transparency logs for subdomain discovery. Playwright adds page "
     "screenshots to the evidence."),
    ("What does an OpenScore report include?",
     "An OpenScore report is a single offline HTML file with the overall grade, a score for each "
     "factor, priority fixes ranked by score gain, and every finding with evidence, a verify "
     "command and remediation.",
     "Each scan also writes a JSON file, PNG evidence exhibits, an audit log, and a comparison with "
     "the previous scan of the same domain."),
  ]),
  ("Findings and remediation", [
    ("How does OpenScore handle false positives?",
     "OpenScore avoids most false positives by design and lets you triage the rest as a false "
     "positive, accepted risk or compensating control, with a reason, approver and review date.",
     "DNS errors are never treated as missing records, exposed-file checks match on content rather "
     "than an HTTP 200 response, and version-based findings are marked tentative. Triaged findings "
     "leave the score but stay visible in the report. See "
     "[handling false positives](" + DOCS + "FALSE_POSITIVES.md)."),
    ("Does OpenScore give Microsoft 365 remediation steps?",
     "Yes. OpenScore's remediation includes Microsoft 365, Exchange Online and Entra ID specifics "
     "where they apply, such as enabling DKIM signing and SPF records for Microsoft 365.",
     "Hostnames that point to vendor services such as Microsoft 365 are recognized and labeled with "
     "the vendor's name; their findings count, with a note on whether the fix is a vendor setting."),
    ("Can I track OpenScore findings over time?",
     "Yes. Each OpenScore scan is compared with the previous one, listing new and resolved findings "
     "and the score change.",
     "Every finding in the JSON report has a key that stays the same between scans, so you can "
     "build a tracker or tickets from it. See "
     "[tracking findings with Claude](" + DOCS + "tracking-findings.md)."),
    ("How do I report a bug or a security issue in OpenScore?",
     "Report bugs as GitHub issues, and report security vulnerabilities in OpenScore privately "
     "through GitHub's private vulnerability reporting, as described in SECURITY.md.",
     "Please don't open a public issue for a vulnerability."),
  ]),
]
