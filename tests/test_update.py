"""`openscore --update` against throwaway git repos (needs git on PATH; skipped otherwise).
Run: python -m pytest tests/"""
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openscore import update  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")

ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_NOSYSTEM": "1"}


def git(cwd, *args):
    r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, encoding="utf-8",
                       env={**os.environ, **ENV})
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def commit(repo, files: dict, msg):
    for rel, text in files.items():
        write(os.path.join(repo, rel), text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)
    git(repo, "push", "-q", "origin", "HEAD:main")


@pytest.fixture
def repos(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    d = tempfile.mkdtemp()
    origin, dev, user = (os.path.join(d, n) for n in ("origin.git", "dev", "user"))
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", origin], check=True)
    subprocess.run(["git", "clone", "-q", origin, dev], check=True, capture_output=True)
    git(dev, "symbolic-ref", "HEAD", "refs/heads/main")   # whatever init.defaultBranch is
    commit(dev, {"openscore/__init__.py": '__version__ = "0.2.0"\n', "requirements.txt": "requests\n",
                 "README.md": "v1\n"}, "initial")
    subprocess.run(["git", "clone", "-q", origin, user], check=True, capture_output=True)
    yield dev, user
    shutil.rmtree(d, ignore_errors=True)


def test_already_up_to_date(repos, capsys):
    _, user = repos
    assert update.run(user, pip=lambda r: pytest.fail("pip should not run")) == 0
    assert "Already up to date (OpenScore 0.2.0)" in capsys.readouterr().out


def test_fast_forward_without_reinstall(repos, capsys):
    dev, user = repos
    commit(dev, {"README.md": "v2\n", "openscore/__init__.py": '__version__ = "0.2.1"\n'}, "dark mode")
    assert update.run(user, pip=lambda r: pytest.fail("pip should not run")) == 0
    out = capsys.readouterr().out
    assert "OpenScore 0.2.0 -> 0.2.1" in out and "dark mode" in out and "requirements unchanged" in out
    assert git(user, "rev-parse", "HEAD") == git(dev, "rev-parse", "HEAD")


def test_requirements_change_triggers_pip(repos):
    dev, user = repos
    commit(dev, {"requirements.txt": "requests\ndnspython\n"}, "new dep")
    calls = []
    assert update.run(user, pip=lambda r: calls.append(r) or 0) == 0
    assert calls == [user]


def test_refuses_with_local_edits(repos, capsys):
    dev, user = repos
    commit(dev, {"README.md": "v2\n"}, "upstream change")
    write(os.path.join(user, "README.md"), "my local edit\n")
    assert update.run(user) == 1
    assert "local changes" in capsys.readouterr().out
    assert open(os.path.join(user, "README.md"), encoding="utf-8").read() == "my local edit\n"


def test_untracked_files_are_fine(repos):
    dev, user = repos
    write(os.path.join(user, "suppressions", "client.com.toml"), "# mine\n")   # untracked: kept
    commit(dev, {"README.md": "v2\n"}, "upstream change")
    assert update.run(user, pip=lambda r: 0) == 0
    assert os.path.exists(os.path.join(user, "suppressions", "client.com.toml"))


def test_not_a_git_checkout(capsys):
    d = tempfile.mkdtemp()
    try:
        assert update.run(d) == 1
        assert "not a git checkout" in capsys.readouterr().out
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_system_package_install_points_to_apt(capsys):
    d = tempfile.mkdtemp()
    try:
        root = os.path.join(d, "usr", "lib", "python3", "dist-packages")
        os.makedirs(os.path.join(root, "openscore"))
        assert update.run(root) == 1
        assert "apt install --only-upgrade openscore" in capsys.readouterr().out
        venv = os.path.join(d, "venv", "lib", "python3.12", "site-packages")
        os.makedirs(os.path.join(venv, "openscore"))
        assert update.run(venv) == 1
        assert "pip install --upgrade openscore" in capsys.readouterr().out
    finally:
        shutil.rmtree(d, ignore_errors=True)
