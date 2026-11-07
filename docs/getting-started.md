# Getting started

OpenScore runs on Linux and Windows with Python 3.11 or newer. Everything beyond Python is
optional: OpenScore uses nmap, nuclei, subfinder, testssl.sh and Playwright when they're installed
and falls back to built-in checks when they aren't.

## Install

### Linux

```bash
git clone https://github.com/himynameislee/OpenScore.git openscore && cd openscore
./install_linux.sh
```

The installer installs the Python requirements and, where your package manager has them, the
optional tools. You can also install the requirements yourself with
`pip install -r requirements.txt` and add tools later.

### Windows 10/11

```powershell
git clone https://github.com/himynameislee/OpenScore.git openscore; cd openscore
powershell -ExecutionPolicy Bypass -File .\install_windows.ps1
```

The installer sets up Python (through winget if needed), the Python requirements and Nmap, and
downloads nuclei and subfinder into `.\tools\`. Run OpenScore with `.\openscore.bat`.

- **testssl.sh** is a bash tool, so on Windows OpenScore uses its built-in TLS checks instead (or
  run OpenScore under WSL).
- **Nmap on Windows needs [Npcap](https://npcap.com).** Without it, OpenScore uses its own TCP
  connect scanner.

### Standalone binaries

`openscore-windows-x64.exe` and `openscore-linux-x64` are on the
[Releases](https://github.com/himynameislee/OpenScore/releases) page. They need no Python, with
two limits:

- **They don't take page screenshots.** Install from source if you want screenshots in the evidence.
- **They only find nuclei and subfinder on your PATH or in a `tools` folder next to the binary**,
  never in the current folder (that would let a planted executable run). A binary run straight from
  Downloads has neither, so subdomain discovery falls back to certificate logs and common names.
  For full discovery, put the binary in its own folder with `tools\subfinder.exe` (and
  `tools\nuclei.exe` for active scans) next to it.

### Debian package

The repository includes Debian packaging. Until OpenScore is in a distribution's repositories, you
can build the package yourself; see [CONTRIBUTING.md](../CONTRIBUTING.md#debian-package).

### Updating

```bash
python3 -m openscore --update        # Windows: .\openscore.bat --update
```

For git installs this fast-forwards your checkout, shows what changed, and reinstalls Python
packages only if `requirements.txt` changed. Your `reports/`, `suppressions/` and `tools/` folders
are left alone, and if you've edited OpenScore's own files it stops rather than overwrite them.
Standalone binaries can't update themselves; download the new release. On a Debian package
install, `--update` prints the `apt` command to run instead.

## Your first scan

Start with a passive + light scan. It's safe on any domain: it reads public data and makes the same
requests a normal visitor's browser would.

```bash
python3 -m openscore example.com --client "Example Inc" --open
```

`--open` opens the report in your browser when the scan finishes. On Windows, use
`.\openscore.bat` in place of `python3 -m openscore`.

When you're authorized to test the organization, add `--active` and an authorization reference:

```bash
python3 -m openscore example.com --client "Example Inc" \
    --ips 203.0.113.16/28 --active \
    --authorization "SOW-114 signed J. Smith 2026-11-01" --open
```

OpenScore shows the scope and asks you to type the domain to confirm before any active check
runs. See [Modes, scope and authorization](modes-and-scope.md) before running your first active
scan, and keep in mind that active scans take much longer: nuclei and testssl.sh can run for an
hour or more on a large estate.

### What you'll see while it runs

The console logs each module as it starts (`── discovery (passive)`, `── web (light)` and so on),
the number of hosts found, and, for the long-running tools, a progress line every minute:

```
nuclei 19% · 46178/238173 requests · 0 matches · 0:17:00 elapsed
testssl.sh 3/12 portal.example.com:443
```

**Ctrl+C** during nuclei stops only nuclei, and during testssl.sh it skips the remaining hosts. In
both cases the scan carries on and the report says what was skipped. Ctrl+C during any other module
stops the scan and writes a partial report.

When it finishes, it prints the overall score, each factor's score and the paths of the report
files.

## Output

Everything goes to `./reports/` (change it with `-o DIR`):

| File | Contents |
|---|---|
| `<domain>-<time>.html` | The report: one self-contained file with no outside resources. Print → Save as PDF works. |
| `<domain>-<time>.json` | All results as data. The next scan of the same domain compares itself against this file. |
| `<domain>-<time>.audit.log` | Timestamped record of the scan: who ran it, the authorization reference and every active action. |
| `<domain>-<time>-evidence/` | PNG evidence exhibits and page screenshots (also embedded in the HTML). |
| `<domain>-<time>.suppressions-template.toml` | Only with `--emit-suppressions`: every open finding as a commented suppressions entry. |

The timestamp is to the minute, so **two scans of the same domain started in the same minute
overwrite each other's files**. Wait a minute between runs, or use a different `-o` folder.

Reports contain the target's hostnames, IP addresses and findings. Treat them like any other
assessment deliverable: store them where only the people who need them can read them.

## API keys (optional)

Some data sources work better or only with a key. Set keys as environment variables rather than
command-line flags, so they don't end up in your shell history:

| Variable | Service | Notes |
|---|---|---|
| `ABUSEIPDB_KEY` | AbuseIPDB | Free account, 1,000 checks per day |
| `GREYNOISE_KEY` | GreyNoise Community | Works without a key, but rate-limited |
| `HIBP_KEY` | Have I Been Pwned | Paid; the domain must be verified in your HIBP dashboard |

On Linux, a simple approach is a file only you can read, loaded by your shell:

```bash
cat > ~/.openscore.env <<'EOF'
export ABUSEIPDB_KEY=...
export GREYNOISE_KEY=...
EOF
chmod 600 ~/.openscore.env
echo '[ -f ~/.openscore.env ] && . ~/.openscore.env' >> ~/.bashrc     # or ~/.zshrc
```

On Windows, use *System Properties → Environment Variables* or
`[Environment]::SetEnvironmentVariable("ABUSEIPDB_KEY", "...", "User")` in PowerShell.

See [Data sources and network use](data-sources.md) for what each service is used for.

## Next steps

- [Reading the report](reading-the-report.md)
- [Handling false positives](FALSE_POSITIVES.md)
- `python3 -m openscore -h` lists every option with examples.
