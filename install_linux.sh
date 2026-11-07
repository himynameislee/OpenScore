#!/usr/bin/env bash
# Installs OpenScore and its optional tools on Linux.
# Uses apt where available (Debian, Ubuntu and derivatives); on other distros it installs the
# Python parts and tells you which optional tools to add with your package manager.
set -euo pipefail
cd "$(dirname "$0")"

TOOLS="nmap nuclei subfinder testssl.sh"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

if command -v apt-get >/dev/null; then
  echo "[*] Installing optional tools with apt: $TOOLS"
  $SUDO apt-get update -qq || echo "[!] apt-get update reported errors from other repos (see above); continuing with cached package lists."
  $SUDO apt-get install -y -qq python3-pip >/dev/null || echo "[!] Could not install python3-pip with apt."
  # One package at a time: not every distro ships all of these, and one missing package
  # must not stop the others from installing.
  for pkg in $TOOLS; do
    if command -v "$pkg" >/dev/null; then
      echo "[=] $pkg already installed"
    elif $SUDO apt-get install -y -qq "$pkg" >/dev/null 2>&1; then
      echo "[+] $pkg installed"
    else
      echo "[-] $pkg is not in your apt repositories (optional)"
    fi
  done
else
  echo "[!] apt-get not found. Install these optional tools with your package manager if you want them: $TOOLS"
fi
for t in nuclei subfinder; do
  command -v "$t" >/dev/null || echo "    $t: download the Linux build from https://github.com/projectdiscovery/$t/releases and put it on your PATH"
done
echo "    All of these are optional; OpenScore falls back to its built-in checks without them."

if command -v nuclei >/dev/null; then
  echo "[*] Updating nuclei templates"
  nuclei -update-templates -silent || true
fi

echo "[*] Installing Python requirements"
python3 -m pip install -q -r requirements.txt 2>/dev/null || python3 -m pip install --break-system-packages -q -r requirements.txt

echo "[*] Installing Playwright from pip (distro python3-playwright packages are often unreliable)"
python3 -m pip install -q --ignore-installed playwright 2>/dev/null || \
  python3 -m pip install --break-system-packages -q --ignore-installed playwright || true

echo "[*] Installing headless Chromium for screenshot evidence"
if python3 -m playwright install chromium && python3 - <<'PY'
import asyncio
from playwright.async_api import async_playwright
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        await b.close()
asyncio.run(main())
print("[+] Chromium launch test OK")
PY
then :; else
  echo "[!] Screenshot support isn't working. Scans still run, just without screenshots."
  echo "    Try: sudo python3 -m playwright install-deps chromium"
fi

echo "[*] Running offline self-test"
python3 tests/test_dns_email.py && python3 tests/test_features.py

cat <<'MSG'

[+] Done. Try a passive scan:
      python3 -m openscore example.com --client "Example Inc"

    Update later with:  python3 -m openscore --update

    Optional API keys (add to ~/.bashrc or ~/.zshrc):
      export ABUSEIPDB_KEY=...     # free: https://www.abuseipdb.com/account/api
      export GREYNOISE_KEY=...     # optional community key
      export HIBP_KEY=...          # paid; domain must be verified in HIBP
MSG
