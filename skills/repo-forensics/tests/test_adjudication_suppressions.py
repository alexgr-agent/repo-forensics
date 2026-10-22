"""Persistent WARN-tier adjudication suppressions (rejected-claim fingerprints).

Covers suppressions.py (fingerprint, eligibility guard, partition, CLI),
scan_history.py store methods, and the aggregate_json / auto_scan wiring.
"""

import json
import os
import subprocess
import sys

import pytest

import aggregate_json
import auto_scan
import scan_history
import suppressions

SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(SCRIPTS_DIR, "scripts")

_POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="run_forensics.sh requires a POSIX shell"
)
SUPPRESSIONS_PY = os.path.join(SCRIPTS_DIR, "suppressions.py")


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "install.sh").write_text("#!/bin/sh\ncurl example.com | sh\n")
    (root / "notes.txt").write_text("hello\n")
    return root


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "history.db")
    monkeypatch.setenv("REPO_FORENSICS_HISTORY_DB", path)
    return path


def _warn_finding(**overrides):
    finding = {
        "scanner": "sast",
        "severity": "medium",
        "title": "Pipe to shell",
        "description": "pipes remote content to shell",
        "file": "install.sh",
        "line": 2,
        "snippet": "curl example.com | sh",
        "category": "test",
        "rule_id": "SA-SH-001",
        "confidence": 0.75,
        "needs_adjudication": True,
    }
    finding.update(overrides)
    return finding


def _add(repo, db, relpath="install.sh", rule_id="SA-SH-001", reason="benign in context"):
    fp_and_hash = suppressions.fingerprint_and_hash(str(repo), relpath, rule_id)
    assert fp_and_hash is not None
    fingerprint, content_hash = fp_and_hash
    result = scan_history.add_suppression_safely(
        fingerprint, rule_id, relpath, content_hash, reason, db_path=db
    )
    assert result is not None
    return fingerprint


# --- fingerprint identity -------------------------------------------------

def test_fingerprint_stable_for_identical_content(repo):
    assert suppressions.fingerprint_for(str(repo), "install.sh", "SA-SH-001") == \
        suppressions.fingerprint_for(str(repo), "install.sh", "SA-SH-001")


def test_fingerprint_changes_on_any_content_edit(repo):
    before = suppressions.fingerprint_for(str(repo), "install.sh", "SA-SH-001")
    with open(repo / "install.sh", "a") as handle:
        handle.write("# one byte different\n")
    after = suppressions.fingerprint_for(str(repo), "install.sh", "SA-SH-001")
    assert before != after


def test_fingerprint_scoped_to_rule_and_file(repo):
    base = suppressions.fingerprint_for(str(repo), "install.sh", "SA-SH-001")
    assert base != suppressions.fingerprint_for(str(repo), "install.sh", "SA-SH-002")
    assert base != suppressions.fingerprint_for(str(repo), "notes.txt", "SA-SH-001")


def test_fingerprint_missing_file_returns_none(repo, tmp_path):
    assert suppressions.fingerprint_for(str(repo), "ghost.sh", "SA-SH-001") is None
    assert suppressions.fingerprint_for(str(tmp_path), "../repo/install.sh", "SA-SH-001") is None


def test_fingerprint_rejects_traversal_and_absolute(repo):
    assert suppressions.fingerprint_for(str(repo), "../../etc/passwd", "X") is None
    assert suppressions.fingerprint_for(str(repo), "/etc/passwd", "X") is None
    assert suppressions.fingerprint_for(str(repo), "", "X") is None
    assert suppressions.fingerprint_for(str(repo), "install.sh", "") is None


def test_fingerprint_symlink_escape_returns_none(repo, tmp_path):
    outside = tmp_path / "outside.sh"
    outside.write_text("x")
    os.symlink(str(outside), repo / "linked.sh")
    assert suppressions.fingerprint_for(str(repo), "linked.sh", "X") is None


# --- eligibility guard ----------------------------------------------------

def test_block_tier_never_eligible(repo, db):
    fingerprint = _add(repo, db)
    findings = [_warn_finding(confidence=0.95)]
    active, suppressed = suppressions.partition_suppressed(
        findings, str(repo), suppressions.load_active_records(db))
    assert len(active) == 1 and suppressed == []
    assert suppressions.load_active_records(db)[0]["fingerprint"] == fingerprint


def test_correlation_never_eligible(repo, db):
    _add(repo, db)
    findings = [_warn_finding(scanner="correlation")]
    active, suppressed = suppressions.partition_suppressed(
        findings, str(repo), suppressions.load_active_records(db))
    assert len(active) == 1 and suppressed == []


def test_missing_rule_id_or_file_never_eligible(repo, db):
    _add(repo, db)
    records = suppressions.load_active_records(db)
    for broken in (_warn_finding(rule_id=""), _warn_finding(file=""),
                   _warn_finding(confidence="not-a-number"),
                   _warn_finding(confidence=0.59), _warn_finding(confidence=0.92)):
        active, suppressed = suppressions.partition_suppressed([broken], str(repo), records)
        assert len(active) == 1 and suppressed == []


def test_exact_match_is_suppressed_and_annotated(repo, db):
    fingerprint = _add(repo, db, reason="example code, not executed")
    records = suppressions.load_active_records(db)
    active, suppressed = suppressions.partition_suppressed(
        [_warn_finding()], str(repo), records)
    assert active == []
    assert len(suppressed) == 1
    entry = suppressed[0]
    assert "needs_adjudication" not in entry
    assert entry["suppression_source"] == "adjudication"
    assert entry["suppression"]["fingerprint"] == fingerprint
    assert entry["suppression"]["reason"] == "example code, not executed"


def test_edited_content_re_fires(repo, db):
    _add(repo, db)
    with open(repo / "install.sh", "a") as handle:
        handle.write("echo changed\n")
    active, suppressed = suppressions.partition_suppressed(
        [_warn_finding()], str(repo), suppressions.load_active_records(db))
    assert len(active) == 1 and suppressed == []
    assert active[0].get("needs_adjudication") is True


# --- store behavior --------------------------------------------------------

def test_read_path_never_creates_db(tmp_path, monkeypatch):
    db = str(tmp_path / "subdir" / "history.db")
    monkeypatch.setenv("REPO_FORENSICS_HISTORY_DB", db)
    assert suppressions.load_active_records() == []
    assert not os.path.exists(db)
    assert not os.path.exists(os.path.dirname(db))


def test_corrupt_db_is_failure_safe(tmp_path, monkeypatch):
    db = tmp_path / "history.db"
    db.write_bytes(b"this is not sqlite")
    monkeypatch.setenv("REPO_FORENSICS_HISTORY_DB", str(db))
    assert suppressions.load_active_records() == []
    findings = [_warn_finding()]
    active, suppressed = suppressions.partition_suppressed(findings, "/repo", [])
    assert active == findings and suppressed == []


def test_revoke_by_unique_prefix_and_ambiguity(repo, db):
    _add(repo, db, relpath="install.sh", rule_id="SA-SH-001")
    _add(repo, db, relpath="notes.txt", rule_id="SA-SH-009")
    store = scan_history.HistoryStore(db)
    fps = [r["fingerprint"] for r in store.list_suppressions()]
    # An empty (or shared) prefix matches more than one record: refuse.
    with pytest.raises(ValueError):
        store.revoke_suppression("")
    # A unique prefix revokes exactly that record.
    prefix = fps[0][:12]
    if prefix != fps[1][:12]:
        assert store.revoke_suppression(prefix) == 1
    else:  # astronomically unlikely; fall back to exact match semantics
        assert store.revoke_suppression(fps[0]) == 1
    assert [r["fingerprint"] for r in store.list_suppressions()] == [fps[1]]
    # Exact fingerprint revokes; unknown prefix returns 0; clear empties.
    assert store.revoke_suppression(fps[1]) == 1
    assert store.revoke_suppression("deadbeef") == 0
    assert store.clear_suppressions() == 0


def test_add_refreshes_existing_record(repo, db):
    _add(repo, db, reason="first")
    _add(repo, db, reason="second")
    records = scan_history.HistoryStore(db).list_suppressions()
    assert len(records) == 1
    assert records[0]["reason"] == "second"


# --- aggregate_json wiring -------------------------------------------------

def _write_scanner_output(tmp_path, name, findings, exit_code="1"):
    (tmp_path / f"{name}.out").write_text(json.dumps(findings))
    (tmp_path / f"{name}.err").write_text("")
    (tmp_path / f"{name}.exit").write_text(exit_code)


def test_aggregate_report_applies_suppression(repo, db, tmp_path):
    _add(repo, db, reason="adjudicated benign")
    results = tmp_path / "results"
    results.mkdir()
    _write_scanner_output(results, "sast", [_warn_finding()])

    report = aggregate_json.build_report(str(results), str(repo), "false")

    assert report["summary"]["total"] == 0
    assert report["exit_code"] == 0
    assert not any(f.get("needs_adjudication") for f in report["findings"])
    assert len(report["suppressed"]) == 1
    assert report["suppressed"][0]["suppression_source"] == "adjudication"
    supp = report["adjudication_suppressions"]
    assert len(supp["applied"]) == 1
    assert supp["applied"][0]["rule_id"] == "SA-SH-001"
    assert len(supp["active"]) == 1


def test_aggregate_report_block_survives_suppression_record(repo, db, tmp_path):
    _add(repo, db)
    results = tmp_path / "results"
    results.mkdir()
    _write_scanner_output(results, "sast",
                          [_warn_finding(confidence=0.95, severity="critical")],
                          exit_code="2")

    report = aggregate_json.build_report(str(results), str(repo), "false")

    assert report["exit_code"] == 2
    assert report["summary"]["total"] == 1
    assert report["suppressed"] == []
    assert report["adjudication_suppressions"]["applied"] == []
    assert len(report["adjudication_suppressions"]["active"]) == 1


def test_aggregate_text_report_lists_suppressions(repo, db, tmp_path):
    _add(repo, db, reason="adjudicated benign")
    results = tmp_path / "results"
    results.mkdir()
    _write_scanner_output(results, "sast", [_warn_finding()])
    report = aggregate_json.build_report(str(results), str(repo), "false")

    text = aggregate_json.format_report_as_text(report)
    assert "ADJUDICATION SUPPRESSIONS: 1 active (1 applied this run)" in text
    assert "adjudicated benign" in text
    assert "revoke" in text and "--all" in text
    assert "ADJUDICATION REQUIRED" not in text


def test_clean_report_has_no_suppression_section(repo, db, tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    _write_scanner_output(results, "sast", [], exit_code="0")
    report = aggregate_json.build_report(str(results), str(repo), "false")
    text = aggregate_json.format_report_as_text(report)
    assert "ADJUDICATION SUPPRESSIONS" not in text
    assert report["adjudication_suppressions"] == {"applied": [], "active": []}


# --- auto_scan wiring ------------------------------------------------------

def test_auto_scan_format_output_reports_suppressions(repo, db):
    _add(repo, db)
    kept, suppressed = auto_scan.apply_adjudication_suppressions(
        [_warn_finding()], str(repo))
    assert kept == [] and len(suppressed) == 1
    output = auto_scan.format_output(
        [], "git clone x", "git_clone", "repo", adjudication_suppressed=suppressed)
    assert "suppressed by prior adjudication" in output
    assert "ADJUDICATION REQUIRED" not in output


def test_auto_scan_filter_failure_safe(repo, monkeypatch):
    monkeypatch.setenv("REPO_FORENSICS_HISTORY_DB",
                       os.path.join(str(repo), "no-such-dir", "h.db"))
    findings = [_warn_finding()]
    kept, suppressed = auto_scan.apply_adjudication_suppressions(findings, str(repo))
    assert kept == findings and suppressed == []


def test_auto_scan_block_survives_suppression(repo, db):
    _add(repo, db)
    kept, suppressed = auto_scan.apply_adjudication_suppressions(
        [_warn_finding(confidence=0.95)], str(repo))
    assert len(kept) == 1 and suppressed == []


# --- CLI -------------------------------------------------------------------

def _run_cli(*argv, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, SUPPRESSIONS_PY, *argv],
        capture_output=True, text=True, env=env, timeout=60,
    )


def test_cli_add_list_revoke_roundtrip(repo, db):
    env = {"REPO_FORENSICS_HISTORY_DB": db}
    result = _run_cli("add", "--repo", str(repo), "--file", "install.sh",
                      "--rule-id", "SA-SH-001", "--reason", "benign", env_extra=env)
    assert result.returncode == 0, result.stderr
    assert "suppressed" in result.stdout

    result = _run_cli("list", env_extra=env)
    assert result.returncode == 0
    assert "SA-SH-001" in result.stdout and "install.sh" in result.stdout
    assert "benign" in result.stdout

    result = _run_cli("list", "--json", env_extra=env)
    payload = json.loads(result.stdout)
    assert len(payload) == 1
    fingerprint = payload[0]["fingerprint"]

    result = _run_cli("revoke", "--fingerprint", fingerprint[:12], env_extra=env)
    assert result.returncode == 0, result.stderr
    result = _run_cli("list", env_extra=env)
    assert "no active" in result.stdout


def test_cli_add_requires_reason_and_real_file(repo, db):
    env = {"REPO_FORENSICS_HISTORY_DB": db}
    result = _run_cli("add", "--repo", str(repo), "--file", "install.sh",
                      "--rule-id", "SA-SH-001", "--reason", "  ", env_extra=env)
    assert result.returncode == 2
    result = _run_cli("add", "--repo", str(repo), "--file", "ghost.sh",
                      "--rule-id", "SA-SH-001", "--reason", "x", env_extra=env)
    assert result.returncode == 2
    result = _run_cli("add", "--repo", str(repo), "--file", "../../etc/passwd",
                      "--rule-id", "SA-SH-001", "--reason", "x", env_extra=env)
    assert result.returncode == 2
    assert not os.path.exists(db)  # refused adds never create the DB


def test_cli_reason_is_sanitized(repo, db):
    env = {"REPO_FORENSICS_HISTORY_DB": db}
    result = _run_cli("add", "--repo", str(repo), "--file", "install.sh",
                      "--rule-id", "SA-SH-001",
                      "--reason", "ok\x1b[31m\u202e hidden", env_extra=env)
    assert result.returncode == 0
    records = scan_history.HistoryStore(db).list_suppressions()
    assert "\x1b" not in records[0]["reason"]
    assert "\u202e" not in records[0]["reason"]


def test_cli_revoke_all_and_unknown(repo, db):
    env = {"REPO_FORENSICS_HISTORY_DB": db}
    _run_cli("add", "--repo", str(repo), "--file", "install.sh",
             "--rule-id", "SA-SH-001", "--reason", "x", env_extra=env)
    result = _run_cli("revoke", "--fingerprint", "deadbeef", env_extra=env)
    assert result.returncode == 2
    result = _run_cli("revoke", "--all", env_extra=env)
    assert result.returncode == 0
    assert "revoked 1" in result.stdout


def test_cli_revoke_on_missing_db(tmp_path):
    env = {"REPO_FORENSICS_HISTORY_DB": str(tmp_path / "none.db")}
    result = _run_cli("revoke", "--all", env_extra=env)
    assert result.returncode == 0
    assert "no active" in result.stdout


# --- focused-mode scanner count -------------------------------------------

@_POSIX_ONLY
def test_focused_mode_count_matches_launcher(repo):
    """The --skill-scan banner count must equal the number of scanners the
    launcher actually starts (the old hardcoded 18 drifted to 19 launches)."""
    import re as _re

    script = os.path.join(SCRIPTS_DIR, "run_forensics.sh")
    result = subprocess.run(
        ["bash", script, str(repo), "--skill-scan", "--format", "json", "--offline"],
        capture_output=True, text=True, timeout=300,
    )
    report = json.loads(result.stdout)
    scanner_names = [s["name"] for s in report["scanners"] if s["name"] != "correlation"]

    text = subprocess.run(
        ["bash", script, str(repo), "--skill-scan", "--format", "text", "--offline"],
        capture_output=True, text=True, timeout=300,
    ).stdout
    match = _re.search(r"Running focused skill scan \((\d+) scanners\)", text)
    assert match, f"banner missing; stdout head: {text[:400]}"
    assert int(match.group(1)) == len(scanner_names)
