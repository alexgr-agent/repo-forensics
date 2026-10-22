#!/usr/bin/env python3
"""Fail when repo-forensics finds something new in its own code.

A security scanner holds the same code it hunts for, so a self-scan is never
empty. This gate compares the current self-scan against the reviewed known
list in .github/selfscan-baseline.json and fails on anything new at medium
severity or above. Findings are matched by scanner, rule, file and severity,
never by line number, so ordinary edits do not trip it.

  python3 scripts/selfscan_gate.py              # scan a clean export of HEAD and compare
  python3 scripts/selfscan_gate.py --report r.json   # compare an existing JSON report
  python3 scripts/selfscan_gate.py --update     # rewrite the known list (review the diff!)

Exit codes: 0 clean, 1 new findings, 2 the scan itself failed.
"""

import argparse
import collections
import json
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, ".github", "selfscan-baseline.json")
RUNNER = os.path.join(ROOT, "skills", "repo-forensics", "scripts", "run_forensics.sh")
GATED = ("critical", "high", "medium")
# Findings that describe the scan environment, not the code: they differ
# between a laptop and a CI runner and say nothing about a change.
ENVIRONMENT_SCANNERS = frozenset({"meta", "git_forensics", "dependencies"})


def finding_key(finding):
    return "|".join((
        str(finding.get("scanner", "")),
        str(finding.get("rule_id") or finding.get("title", "")),
        str(finding.get("file", "")),
        str(finding.get("severity", "")),
    ))


def gated_counts(report):
    counts = collections.Counter()
    for finding in report.get("findings", []):
        if finding.get("severity") not in GATED:
            continue
        if finding.get("scanner") in ENVIRONMENT_SCANNERS:
            continue
        counts[finding_key(finding)] += 1
    return counts


def new_findings(current, baseline):
    """Keys whose count grew past the known list, with how many are new."""
    return {key: n - baseline.get(key, 0)
            for key, n in sorted(current.items()) if n > baseline.get(key, 0)}


def scan_head():
    """Self-scan a clean `git archive HEAD` export (no .git, no untracked files)."""
    with tempfile.TemporaryDirectory(prefix="rf-selfscan-") as tmp:
        tree = os.path.join(tmp, "tree")
        os.mkdir(tree)
        archive = os.path.join(tmp, "head.tar")
        subprocess.run(["git", "-C", ROOT, "archive", "-o", archive, "HEAD"], check=True)
        with tarfile.open(archive) as tar:
            tar.extractall(tree, filter="data")
        result = subprocess.run(
            ["bash", RUNNER, tree, "--format", "json", "--offline"],
            capture_output=True, text=True, timeout=1800,
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            sys.stderr.write(result.stderr[-4000:])
            raise SystemExit("[!] self-scan produced no JSON report")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", help="existing run_forensics JSON report to compare")
    parser.add_argument("--baseline", default=BASELINE)
    parser.add_argument("--update", action="store_true", help="rewrite the known list")
    args = parser.parse_args(argv)

    try:
        report = json.load(open(args.report, encoding="utf-8")) if args.report else scan_head()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"[!] self-scan failed: {exc}", file=sys.stderr)
        return 2
    current = gated_counts(report)

    if args.update:
        with open(args.baseline, "w", encoding="utf-8") as handle:
            json.dump({"gated_severities": list(GATED), "findings": dict(sorted(current.items()))},
                      handle, indent=2, sort_keys=False)
            handle.write("\n")
        print(f"known list updated: {sum(current.values())} findings in {args.baseline}")
        return 0

    try:
        with open(args.baseline, encoding="utf-8") as handle:
            baseline = collections.Counter(json.load(handle)["findings"])
    except (OSError, ValueError, KeyError) as exc:
        print(f"[!] cannot read known list {args.baseline}: {exc}", file=sys.stderr)
        return 2

    fresh = new_findings(current, baseline)
    if fresh:
        print(f"self-scan: {sum(fresh.values())} new finding(s) not in the known list:")
        for key, n in fresh.items():
            scanner, rule, path, severity = key.split("|", 3)
            print(f"  {severity:8} {scanner:18} {rule:30} {path}  (+{n})")
        print("Fix the code, or if the finding is reviewed and expected, run "
              "`python3 scripts/selfscan_gate.py --update` and commit the known list.")
        return 1
    gone = sum((baseline - current).values())
    print(f"self-scan: no new findings ({sum(current.values())} known"
          + (f", {gone} resolved; consider --update" if gone else "") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
