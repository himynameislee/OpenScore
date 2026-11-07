"""Self-update for git installs: `openscore --update`.

Fetches only what changed from the git remote (no full re-download), fast-forwards the
checkout, and reinstalls Python requirements only if requirements.txt changed. It never
touches scan targets, and it refuses to run if you have local edits or local commits, so
nothing of yours is overwritten.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

from . import REPO_URL

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git(root: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def _version(root: str) -> str:
    try:
        with open(os.path.join(root, "openscore", "__init__.py"), encoding="utf-8") as f:
            m = re.search(r'__version__\s*=\s*"([^"]+)"', f.read())
        return m.group(1) if m else "?"
    except OSError:
        return "?"


def _pip_install(root: str) -> int:
    """pip install -r requirements.txt with the interpreter running OpenScore.
    Debian-based distros mark the system Python as externally managed (PEP 668); the installer
    uses --break-system-packages there, so do the same, but only when pip asks for it."""
    cmd = [sys.executable, "-m", "pip", "install", "-q", "-r", os.path.join(root, "requirements.txt")]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0 and "externally-managed" in (r.stderr + r.stdout):
        r = subprocess.run(cmd + ["--break-system-packages"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(r.stderr.strip()[-2000:], file=sys.stderr)
    return r.returncode


def run(root: str = ROOT, pip=_pip_install) -> int:
    say = lambda msg: print(msg, flush=True)   # noqa: E731

    if getattr(sys, "frozen", False):
        say("[!] This is the standalone OpenScore binary; it can't update itself.\n"
            f"    Download the latest release from {REPO_URL}/releases\n"
            f"    or switch to a git clone (git clone {REPO_URL}.git openscore) and use `--update` from then on.")
        return 1
    if not shutil.which("git"):
        say("[!] git is not installed, so OpenScore can't fetch updates.\n"
            "    Linux: sudo apt install git (or your package manager)    Windows: winget install Git.Git")
        return 1
    pkg_dir = os.path.join(root, "openscore")
    if not os.path.isdir(os.path.join(root, ".git")) and f"{os.sep}dist-packages{os.sep}" in pkg_dir + os.sep:
        say("[!] OpenScore was installed by your system package manager; update it with:\n"
            "      sudo apt update && sudo apt install --only-upgrade openscore")
        return 1
    if not os.path.isdir(os.path.join(root, ".git")) and f"{os.sep}site-packages{os.sep}" in pkg_dir + os.sep:
        say("[!] OpenScore was installed with pip; update it with:\n"
            "      python3 -m pip install --upgrade openscore   (or pipx upgrade openscore)")
        return 1
    if not os.path.isdir(os.path.join(root, ".git")):
        say(f"[!] {root} is not a git checkout (installed from a zip?), so there is nothing to update from.\n"
            "    Switch once to a clone and future updates only download the changes:\n"
            f"      git clone {REPO_URL}.git openscore && cd openscore && ./install_linux.sh   (or install_windows.ps1)\n"
            "    Copy over anything you keep locally first (suppressions/*.toml, reports/).")
        return 1

    branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    if not branch or branch == "HEAD":
        say("[!] The checkout is not on a branch (detached HEAD). Run `git checkout main` first.")
        return 1

    # Refuse to clobber local edits to tracked files. Untracked/ignored files (reports/,
    # suppressions/*.toml, tools/) are never touched by a fast-forward, so they're fine.
    dirty = _git(root, "status", "--porcelain", "--untracked-files=no").stdout.strip()
    if dirty:
        say("[!] You have local changes to OpenScore files; not updating so they aren't lost:")
        for line in dirty.splitlines()[:20]:
            say(f"      {line}")
        say("    Keep them:    git stash  ->  openscore --update  ->  git stash pop\n"
            "    Drop them:    git checkout -- .  ->  openscore --update")
        return 1

    old = _git(root, "rev-parse", "HEAD").stdout.strip()
    old_ver = _version(root)
    say(f"[*] Checking for updates ({branch} @ {old[:7]}, OpenScore {old_ver}) ...")
    f = _git(root, "fetch", "--quiet", "origin", branch)
    if f.returncode != 0:
        say("[!] Could not reach the git remote:\n    " + (f.stderr.strip() or "git fetch failed").replace("\n", "\n    "))
        say("    (Private repo? Make sure git can log in: `gh auth login`, or a credential helper.)")
        return 1
    new = _git(root, "rev-parse", "FETCH_HEAD").stdout.strip()

    if new == old:
        say(f"[=] Already up to date (OpenScore {old_ver}).")
        return 0
    if _git(root, "merge-base", "--is-ancestor", old, new).returncode != 0:
        say("[!] Your checkout has local commits that aren't on the remote, so it can't be fast-forwarded.\n"
            f"    Look at them with `git log origin/{branch}..HEAD` and push or reset them, then retry.")
        return 1

    incoming = _git(root, "log", "--oneline", "--no-decorate", f"{old}..{new}").stdout.strip().splitlines()
    m = _git(root, "merge", "--ff-only", "--quiet", new)
    if m.returncode != 0:
        say("[!] Update failed:\n    " + m.stderr.strip())
        return 1
    changed = set(_git(root, "diff", "--name-only", old, new).stdout.split())

    new_ver = _version(root)
    ver = f"{old_ver} -> {new_ver}" if new_ver != old_ver else new_ver
    say(f"[+] Updated {old[:7]} -> {new[:7]} (OpenScore {ver}), {len(incoming)} change(s):")
    for line in incoming[:15]:
        say(f"      {line}")
    if len(incoming) > 15:
        say(f"      ... and {len(incoming) - 15} more")

    if "requirements.txt" in changed:
        say("[*] requirements.txt changed - installing Python packages ...")
        if pip(root) != 0:
            say("[!] pip install failed (see above). Run it manually:\n"
                f"    {os.path.basename(sys.executable)} -m pip install -r requirements.txt")
            return 1
    else:
        say("[=] Python requirements unchanged - nothing to install.")
    if changed & {"install_linux.sh", "install_windows.ps1"}:
        say("[i] The installer changed (new or updated external tools). Re-run it when convenient:\n"
            "    ./install_linux.sh    or    powershell -ExecutionPolicy Bypass -File .\\install_windows.ps1")
    return 0
