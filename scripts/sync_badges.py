#!/usr/bin/env python3
"""
sync_badges.py - keep the README badges and diagram counts honest, automatically.

The README "scanners" and "tests" badges, the prose counts, and the numbers
embedded in the hero/pipeline diagrams used to be hand-maintained and drifted on
every release (v2.11.0 shipped with "20 scanners / 1,551 tests" still showing).
This script computes the real numbers from the source of truth and writes them
everywhere they appear, so a stale count is impossible.

Sources of truth:
  - scanners: number of `scan_*.py` files that declare a `SCANNER_NAME` (the
    canonical scanner marker). It must equal the FULL_SCANNERS launch list in
    run_forensics.sh (the script refuses to run otherwise).
  - targeted: the PostToolUse / afterShellExecution scanner list in
    auto_scan.run_targeted_scan.
  - tests:    pytest collected-test count.
  - version:  the root .claude-plugin/plugin.json `version`.

Outputs (idempotent — running twice changes nothing):
  - .github/badges/metrics.json  (read live by the README's dynamic shields)
  - README.md prose counts + the "The N Scanners" heading / "Show all N" summary
  - diagrams/hero.svg, scan-verdict.svg, attack-flow.svg, scanner-map.svg
  - plugin manifests, SKILL.md and the Cursor rule (TEXT_SURFACES below)

Run locally any time, and from CI on every push (see .github/workflows/sync-badges.yml).
Pure standard library; no third-party deps (the repo's zero-dependency promise).

Usage:  python3 scripts/sync_badges.py [--check]
        --check exits non-zero if anything is out of date (for CI verification).
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "repo-forensics")
SCRIPTS = os.path.join(SKILL, "scripts")
METRICS = os.path.join(ROOT, ".github", "badges", "metrics.json")


def count_scanners():
    n = 0
    for fn in os.listdir(SCRIPTS):
        # scan_decode is an in-process decode-and-rescan LIBRARY invoked by
        # other scanners, not a standalone parallel scanner -- exclude it so
        # the count matches the documented standalone-scanner set.
        if fn.startswith("scan_") and fn.endswith(".py") and fn != "scan_decode.py":
            with open(os.path.join(SCRIPTS, fn), encoding="utf-8") as f:
                if re.search(r"^SCANNER_NAME\s*=", f.read(), re.M):
                    n += 1
    return n


def full_launch_list():
    """Scanner scripts in run_forensics.sh's FULL_SCANNERS array."""
    with open(os.path.join(SCRIPTS, "run_forensics.sh"), encoding="utf-8") as f:
        body = re.search(r"^FULL_SCANNERS=\((.*?)^\)", f.read(), re.M | re.S)
    if not body:
        return []
    return re.findall(r'"[\w]+:(scan_[\w]+\.py)"', body.group(1))


def count_targeted():
    """Scanners auto_scan.run_targeted_scan launches after an install/clone."""
    with open(os.path.join(SCRIPTS, "auto_scan.py"), encoding="utf-8") as f:
        body = re.search(r"targeted_scanners = \[(.*?)\]", f.read(), re.S)
    return len(re.findall(r"'scan_[\w]+\.py'", body.group(1))) if body else 0


# Every other file that states a scanner count: (path, [(pattern, kind)]).
# kind 'full' = the full audit count, 'targeted' = the post-install count.
TEXT_SURFACES = [
    ("README.md", [(r"\b\d+( scanners below include)", "full"),
                   (r"(Targeted )\d+(-scanner audit)", "targeted")]),
    (".cursor/rules/repo-forensics.mdc", [(r"(full audit, )\d+( scanners)", "full"),
                                          (r"(Targeted )\d+(-scanner audit)", "targeted")]),
    ("skills/repo-forensics/SKILL.md", [(r"(full )\d+(-scanner deep scan)", "full"),
                                        (r"(\*\*)\d+( scanners\*\*)", "full"),
                                        (r"(all )\d+( scanners\))", "full")]),
    (".codex-plugin/plugin.json", [(r"\b\d+( scanners detect)", "full")]),
    (".cursor-plugin/plugin.json", [(r"\b\d+( scanners detect)", "full")]),
    (".kimi-plugin/plugin.json", [(r"\b\d+( scanners detect)", "full")]),
    (".claude-plugin/marketplace.json", [(r"\b\d+( scanners detect)", "full")]),
    ("openclaw/openclaw.plugin.json", [(r"\b\d+( scanners, zero dependencies)", "full")]),
    ("diagrams/scanner-map.svg", [(r"\b\d+(-scanner attack surface map)", "full")]),
]


def _sub_count(pattern, value, text):
    """Replace the number in every match of pattern, keeping the groups."""
    def repl(m):
        if m.re.groups == 2:
            return m.group(1) + str(value) + m.group(2)
        return str(value) + m.group(1)
    return re.sub(pattern, repl, text)


def update_text_surfaces(scanners, targeted, write=True):
    """Rewrite TEXT_SURFACES counts. Returns the files that were stale."""
    counts = {"full": scanners, "targeted": targeted}
    stale = []
    for rel, pats in TEXT_SURFACES:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            orig = f.read()
        new = orig
        for pat, kind in pats:
            new = _sub_count(pat, counts[kind], new)
        if new != orig:
            stale.append(rel)
            if write:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new)
    return stale


def count_tests():
    """pytest collected-test count, or None when collection did not succeed
    (pytest missing, a collection error, or no count in the output). A partial
    or failed collection must never become the published number."""
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        cwd=SKILL, capture_output=True, text=True,
    )
    if res.returncode != 0:
        return None
    # Anchor to the summary line: test ids can contain "N tests collected" too.
    # Anchor to the summary line: test ids can contain "N tests collected" too.
    m = re.search(r"^(\d+)\s+tests? collected", res.stdout, re.M)
    if m:
        return int(m.group(1))
    # Fallback: count "::" test-node lines.
    return sum(1 for line in res.stdout.splitlines() if "::" in line) or None


def read_version():
    with open(os.path.join(ROOT, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        return json.load(f).get("version", "0.0.0")


def _grp(n):
    """Group an int with thousands commas: 1631 -> '1,631'."""
    return f"{n:,}"


def update_readme(text, scanners, tests):
    s = _grp(scanners)  # scanners rarely cross 1000 but be consistent
    t = _grp(tests)
    subs = [
        # static badges (in case the dynamic endpoint is ever reverted)
        (r"(badge/scanners-)\d+(-)", rf"\g<1>{scanners}\g<2>"),
        (r'(alt="N?)\d+( Scanners")', rf"\g<1>{scanners}\g<2>"),
        (r"(badge/tests-)[0-9%C,]+(-)", rf"\g<1>{t.replace(',', '%2C')}\g<2>"),
        (r'(alt=")[\d,]+( Tests")', rf"\g<1>{t}\g<2>"),
        # prose + headings
        (r"(## The )\d+( Scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"(Show all )\d+( scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"\b\d+(-scanner attack surface)", rf"{scanners}\g<1>"),
        (r"(input to )\d+( scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"\b\d+( scanners, runtime behavior)", rf"{scanners}\g<1>"),
        (r"\b\d+( scanners run in parallel)", rf"{scanners}\g<1>"),
        (r"(repo-forensics:\*\* )\d+( scanners)", rf"\g<1>{scanners}\g<2>"),
        (r"[\d,]+( tests across 40)", rf"{t}\g<1>"),
        (r"(All )[\d,]+( tests use synthetic)", rf"\g<1>{t}\g<2>"),
        (r"\*\*[\d,]+( pytest tests)\*\*", rf"**{t}\g<1>**"),
    ]
    for pat, rep in subs:
        text = re.sub(pat, rep, text)
    return text


def update_svgs(scanners):
    changed = []
    targets = {
        "hero.svg": [(r"\b\d+( scanners)", rf"{scanners}\g<1>")],
        "scan-verdict.svg": [(r"(Running all )\d+( scanners)", rf"\g<1>{scanners}\g<2>")],
        "attack-flow.svg": [(r"(across all )\d+( scanners)", rf"\g<1>{scanners}\g<2>")],
    }
    for fn, pats in targets.items():
        path = os.path.join(ROOT, "diagrams", fn)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            orig = f.read()
        new = orig
        for pat, rep in pats:
            new = re.sub(pat, rep, new)
        if new != orig:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
            changed.append(fn)
    return changed


def main():
    check = "--check" in sys.argv
    scanners, tests, version = count_scanners(), count_tests(), read_version()
    targeted = count_targeted()
    missing = [name for name, value in (("scanners", scanners), ("targeted", targeted),
                                        ("tests", tests)) if not value]
    if missing:
        print(f"ERROR: could not compute {', '.join(missing)} (got zero or nothing); "
              f"refusing to write badge counts. For tests, check that pytest is "
              f"installed and `python -m pytest tests/ --collect-only -q` succeeds "
              f"in skills/repo-forensics.", file=sys.stderr)
        sys.exit(2)
    launched = full_launch_list()
    if len(launched) != scanners or len(set(launched)) != len(launched):
        print(f"ERROR: run_forensics.sh FULL_SCANNERS launches {len(launched)} scanners "
              f"but {scanners} scan_*.py files declare SCANNER_NAME; add the new "
              f"scanner to FULL_SCANNERS (or remove the stale entry).", file=sys.stderr)
        sys.exit(2)
    # Flat keys so the README's shields.io dynamic/json badges can query
    # $.scanners / $.tests / $.version directly.
    metrics = {
        "scanners": str(scanners),
        "tests": _grp(tests),
        "version": version,
    }
    dirty = []

    os.makedirs(os.path.dirname(METRICS), exist_ok=True)
    new_metrics = json.dumps(metrics, indent=2) + "\n"
    old_metrics = open(METRICS, encoding="utf-8").read() if os.path.exists(METRICS) else ""
    if new_metrics != old_metrics:
        dirty.append(".github/badges/metrics.json")
        if not check:
            open(METRICS, "w", encoding="utf-8").write(new_metrics)

    readme_path = os.path.join(ROOT, "README.md")
    old_readme = open(readme_path, encoding="utf-8").read()
    new_readme = update_readme(old_readme, scanners, tests)
    if new_readme != old_readme:
        dirty.append("README.md")
        if not check:
            open(readme_path, "w", encoding="utf-8").write(new_readme)

    if check:
        # In check mode SVGs are reported but not written.
        for fn in ("hero.svg", "scan-verdict.svg", "attack-flow.svg"):
            path = os.path.join(ROOT, "diagrams", fn)
            if os.path.exists(path) and re.search(r"\b\d+ scanners", open(path, encoding="utf-8").read()):
                cur = re.search(r"(\d+) scanners", open(path, encoding="utf-8").read())
                if cur and cur.group(1) != str(scanners):
                    dirty.append(f"diagrams/{fn}")
    else:
        dirty += [f"diagrams/{c}" for c in update_svgs(scanners)]

    dirty += update_text_surfaces(scanners, targeted, write=not check)

    print(f"scanners={scanners} targeted={targeted} tests={_grp(tests)} version={version}")
    if dirty:
        print(("OUT OF DATE: " if check else "updated: ") + ", ".join(sorted(set(dirty))))
        if check:
            sys.exit(1)
    else:
        print("all badge surfaces current")


if __name__ == "__main__":
    main()
