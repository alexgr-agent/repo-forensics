"""Every printed scanner count is generated from what actually launches.

N8 (PR #68 review): "28" survived in a dozen places after the 29th scanner
landed. The full-mode banner now counts the FULL_SCANNERS array (like its
FOCUSED_SCANNERS sibling), and scripts/sync_badges.py owns every prose
surface. These tests fail on the next drift instead of a reviewer finding it.
"""

import importlib.util
import os
import re
import subprocess
import sys

import pytest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(SKILL_DIR, "scripts")
REPO_ROOT = os.path.dirname(os.path.dirname(SKILL_DIR))
SYNC_BADGES = os.path.join(REPO_ROOT, "scripts", "sync_badges.py")

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="bash launcher")


def _sync_badges():
    if not os.path.isfile(SYNC_BADGES):
        pytest.skip("sync_badges.py lives in the source repo root only")
    spec = importlib.util.spec_from_file_location("sync_badges", SYNC_BADGES)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_full_launch_list_matches_scanner_files():
    sb = _sync_badges()
    launched = sb.full_launch_list()
    declared = set()
    for fn in os.listdir(SCRIPTS_DIR):
        if fn.startswith("scan_") and fn.endswith(".py") and fn != "scan_decode.py":
            with open(os.path.join(SCRIPTS_DIR, fn), encoding="utf-8") as f:
                if re.search(r"^SCANNER_NAME\s*=", f.read(), re.M):
                    declared.add(fn)
    assert len(launched) == len(set(launched))
    assert set(launched) == declared
    assert sb.count_scanners() == len(launched)


def test_no_stale_scanner_count_on_any_surface():
    sb = _sync_badges()
    stale = sb.update_text_surfaces(sb.count_scanners(), sb.count_targeted(), write=False)
    assert stale == [], f"run python3 scripts/sync_badges.py; stale: {stale}"
    # every README/doc scanner-count phrase states the generated number
    n = sb.count_scanners()
    for rel in ("README.md", "skills/repo-forensics/SKILL.md", ".codex-plugin/plugin.json",
                ".cursor-plugin/plugin.json", ".claude-plugin/marketplace.json",
                ".kimi-plugin/plugin.json", "openclaw/openclaw.plugin.json",
                ".cursor/rules/repo-forensics.mdc", "diagrams/scanner-map.svg",
                "diagrams/hero.svg", "diagrams/scan-verdict.svg", "diagrams/attack-flow.svg"):
        text = open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read()
        for m in re.finditer(r"\b(\d+)[- ]scanners?\b", text):
            ctx = text[max(0, m.start() - 60):m.end() + 20]
            if re.search(r"focused|skill-scan|Targeted|column", ctx, re.I):
                continue
            assert int(m.group(1)) == n, f"{rel}: {ctx!r}"


def test_readme_table_lists_every_scanner():
    sb = _sync_badges()
    readme = open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8").read()
    rows = set(re.findall(r"^\| \*\*(\w+)\*\* \|", readme, re.M))
    names = {spec for spec in re.findall(
        r'"(\w+):scan_\w+\.py"',
        re.search(r"^FULL_SCANNERS=\((.*?)^\)",
                  open(os.path.join(SCRIPTS_DIR, "run_forensics.sh"), encoding="utf-8").read(),
                  re.M | re.S).group(1))}
    assert names <= rows, f"README scanner table is missing: {sorted(names - rows)}"


@_POSIX_ONLY
def test_full_mode_banner_counts_what_launches(tmp_path):
    (tmp_path / "a.txt").write_text("hello\n")
    script = os.path.join(SCRIPTS_DIR, "run_forensics.sh")
    usage = subprocess.run(["bash", script], capture_output=True, text=True).stdout
    text = subprocess.run(["bash", script, str(tmp_path), "--format", "text", "--offline",
                           "--no-vulns"], capture_output=True, text=True, timeout=300).stdout
    import json
    payload = json.loads(subprocess.run(
        ["bash", script, str(tmp_path), "--format", "json", "--offline", "--no-vulns"],
        capture_output=True, text=True, timeout=300).stdout)
    launched = [s["name"] for s in payload["scanners"]
                if s["name"] not in ("correlation", "trifecta_raw")]
    banner = re.search(r"Running all (\d+) scanners", text)
    usage_n = re.search(r"Full audit - all (\d+) scanners", usage)
    assert banner and usage_n
    assert int(banner.group(1)) == int(usage_n.group(1)) == len(launched)
