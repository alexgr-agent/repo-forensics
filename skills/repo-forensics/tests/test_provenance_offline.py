"""--offline must keep scan_provenance from calling npm / gh (both contact
their registries). Fake npm and gh binaries log every call; under --offline
the log must stay empty, both for the scanner alone and through
run_forensics.sh."""

import os
import stat
import subprocess
import sys

import pytest

from shell_compat import sh_argv

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="fake binaries are POSIX shell scripts")

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(SKILL_DIR, "scripts", "scan_provenance.py")
RUNNER = os.path.join(SKILL_DIR, "scripts", "run_forensics.sh")


def _setup(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("npm", "gh"):
        fake = bindir / tool
        fake.write_text(
            "#!/bin/sh\n"
            f'echo "{tool} $*" >> "{log}"\n'
            "exit 1\n"
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "x", "version": "1.0.0"}\n')
    (repo / "package-lock.json").write_text(
        '{"name": "x", "lockfileVersion": 3, "packages": {}}\n')
    env = dict(os.environ)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    return repo, log, env


def _calls(log):
    return log.read_text() if log.exists() else ""


def test_scanner_online_calls_fakes(tmp_path):
    """Sanity: the fakes are on PATH and get called without --offline."""
    repo, log, env = _setup(tmp_path)
    subprocess.run([sys.executable, SCANNER, str(repo), "--format", "json"],
                   env=env, capture_output=True, text=True, timeout=60)
    calls = _calls(log)
    assert "npm audit signatures" in calls
    assert "gh attestation verify" in calls


def test_scanner_offline_skips_npm_and_gh(tmp_path):
    repo, log, env = _setup(tmp_path)
    result = subprocess.run(
        [sys.executable, SCANNER, str(repo), "--format", "json", "--offline"],
        env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().startswith("[")
    assert _calls(log) == ""


def test_run_forensics_offline_skips_npm_and_gh(tmp_path):
    repo, log, env = _setup(tmp_path)
    subprocess.run(sh_argv(RUNNER, str(repo), "--offline", "--format", "json"),
                   env=env, capture_output=True, text=True, timeout=300)
    assert _calls(log) == ""
