"""Startup cleanup stops only orphaned scanners from this install."""
import os
import subprocess
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import session_scan  # noqa: E402


def _ps_output(own_dir):
    return "\n".join([
        f"  101     1    05:00 /usr/bin/python3 {own_dir}/scan_sast.py /repo",       # orphan, old: stop
        f"  102  4242    05:00 /usr/bin/python3 {own_dir}/scan_sast.py /repo",       # live parent: keep
        "  103     1    05:00 /usr/bin/python3 /other/repo-forensics/scripts/scan_sast.py /r",  # other install
        f"  104     1    00:30 /usr/bin/python3 {own_dir}/scan_dast.py /repo",       # orphan, young: keep
        f"  105     1 1-02:00:00 /usr/bin/python3 {own_dir}/scan_secrets.py /repo",  # orphan, days old: stop
        "  106     1    09:00 vim /tmp/notes-about-repo-forensics/scan_x.py",        # editor: keep
    ]) + "\n"


def test_only_orphans_from_this_install_are_stopped(monkeypatch):
    own_dir = os.path.dirname(os.path.abspath(session_scan.__file__))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: types.SimpleNamespace(stdout=_ps_output(own_dir)))
    sent = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append(pid))
    assert session_scan._kill_stale_scanners() == ["101", "105"]
    assert sent == [101, 105]


def test_etime_parsing():
    assert session_scan._etime_seconds("05:00") == 300
    assert session_scan._etime_seconds("02:00:00") == 7200
    assert session_scan._etime_seconds("1-00:00:01") == 86401


def test_shell_runner_sweep_is_scoped():
    path = os.path.join(os.path.dirname(__file__), "..", "scripts", "run_forensics.sh")
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    sweep = text[text.index("_stale_pids=$(ps"):text.index("# Handle --verify-install")]
    assert "ppid=" in sweep and "$2 == 1" in sweep
    assert '"$SKILL_DIR/scan_"' in sweep
