# Contributing

Thanks for helping make OpenScore better!

## Dev setup

```bash
git clone https://github.com/himynameislee/OpenScore.git openscore && cd openscore
pip install -r requirements.txt pytest pyflakes
python -m pytest tests/
python tests/fake_target.py &     # misconfigured local lab target
python -m openscore lab.invalid --no-discovery --url https://127.0.0.1:8443/ http://127.0.0.1:8080/ \
    --ips 127.0.0.1/32 --active --authorization "local lab" -y --delay 0 --open
```

## Adding a check

1. **Knowledge base** — add an entry to `CHECKS` in `openscore/kb.py` (factor, severity, title,
   description, remediation, refs) **and** a manual verification command in `VERIFY`.
   A check without a verify step won't be merged: verify steps are how users catch false positives.
2. **Detection** — emit it from the relevant module with `ctx.add("<check_id>", asset, evidence)`.
   * Mark anything inferred from versions/banners/third-party data `confidence="tentative"`.
   * Never treat a DNS/network *error* as proof something is missing.
   * Exposure checks must match on **content**, not just HTTP status.
3. **Mode** — respect the module's `MODE`. Anything that sends more than normal browsing
   traffic to the target belongs in an `active` module and must check `ctx.in_scope()`
   and call `ctx.audit_log()`.
4. **Tests** — add a unit test (see `tests/test_features.py`) and, if possible, plant the issue
   in `tests/fake_target.py` and assert it in CI.
5. **Docs** — run `python3 -m openscore.docgen` to regenerate `docs/check-catalog.md` (and
   `docs/command-reference.md` after changing an option). A test fails if they're out of date.

## Ground rules

* No exploitation, credential guessing, or payload injection — ever.
* No new mandatory paid APIs. Paid/keyed sources must be optional.
* Keep it cross-platform (Linux + Windows): use `encoding="utf-8"` on every file open.

## Debian package

`debian/` builds an `openscore` .deb the way Debian/Kali would (pybuild, man page from `-h`,
autopkgtests in `debian/tests/`). CI builds, lints, installs and tests it on every push.

```bash
sudo apt install build-essential dpkg-dev debhelper dh-python pybuild-plugin-pyproject python3-all help2man lintian
dpkg-buildpackage -us -uc -b        # -> ../openscore_<version>_all.deb
lintian ../openscore_*_amd64.changes
```

New runtime dependencies must exist as Debian packages (python3-*); add them to `pyproject.toml`
and to `Build-Depends` in `debian/control`, and bump `debian/changelog` with each release.

