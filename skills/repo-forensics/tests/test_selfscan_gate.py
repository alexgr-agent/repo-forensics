"""The self-scan gate must go red on a new finding and stay green otherwise."""
import importlib.util
import json
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
GATE = os.path.join(ROOT, "scripts", "selfscan_gate.py")

pytestmark = pytest.mark.skipif(not os.path.isfile(GATE), reason="repo-root scripts not present")


def _gate():
    spec = importlib.util.spec_from_file_location("selfscan_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finding(severity="high", scanner="sast", rule="SA-X-1", path="a.py", line=1):
    return {"scanner": scanner, "rule_id": rule, "file": path, "severity": severity, "line": line}


def _run(tmp_path, known, current):
    gate = _gate()
    report = tmp_path / "r.json"
    baseline = tmp_path / "b.json"
    report.write_text(json.dumps({"findings": known}))
    assert gate.main(["--report", str(report), "--baseline", str(baseline), "--update"]) == 0
    report.write_text(json.dumps({"findings": current}))
    return gate.main(["--report", str(report), "--baseline", str(baseline)])


def test_unchanged_scan_passes(tmp_path):
    assert _run(tmp_path, [_finding()], [_finding()]) == 0


def test_line_moves_do_not_trip(tmp_path):
    assert _run(tmp_path, [_finding(line=3)], [_finding(line=90)]) == 0


@pytest.mark.parametrize("planted", [
    _finding(severity="critical", rule="ST-PI-001", path="SKILL.md"),
    _finding(path="new_file.py"),
    _finding(severity="medium", rule="SA-NEW-9"),
])
def test_new_finding_goes_red(tmp_path, planted):
    assert _run(tmp_path, [_finding()], [_finding(), planted]) == 1


def test_second_copy_of_known_finding_goes_red(tmp_path):
    assert _run(tmp_path, [_finding()], [_finding(), _finding(line=7)]) == 1


def test_low_and_environment_findings_are_not_gated(tmp_path):
    current = [_finding(), _finding(severity="low", path="x.py"),
               _finding(scanner="git_forensics", severity="medium", path=".git")]
    assert _run(tmp_path, [_finding()], current) == 0


def test_missing_known_list_fails_closed(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"findings": []}))
    assert _gate().main(["--report", str(report), "--baseline", str(tmp_path / "none.json")]) == 2
