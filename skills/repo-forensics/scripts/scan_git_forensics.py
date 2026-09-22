#!/usr/bin/env python3
"""
scan_git_forensics.py - Git History Forensics (v2: severity + GPG check)
Analyzes commit history for time anomalies, email inconsistencies,
and unsigned commits.

Created by Alex Greenshpun
"""

import sys
import os
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "git_forensics"


def get_git_log(repo_path):
    # Null byte delimiter prevents author-name spoofing with '|'.
    #
    # The pretty format deliberately does NOT include %G? (signature status):
    # %G? makes git verify each commit's signature, which executes the repo's
    # own gpg.program config value -- arbitrary code execution just from reading
    # a hostile repo's history (the scanner runs inside the untrusted tree). The
    # signature status of an untrusted checkout, verified against whatever keys
    # happen to be in the scanning machine's keyring, is not a meaningful signal
    # anyway (a real third-party signer's key is almost never present, so it
    # reports "cannot check", and an attacker simply leaves commits unsigned).
    # We drop it rather than trust config neutralization alone.
    #
    # The call still goes through the hardened runner, which overrides every
    # exec-capable config key (gpg.program, core.fsmonitor, core.hooksPath, ...)
    # so nothing the repo declares can run during `git log`.
    result = core.run_git_hardened(
        repo_path,
        "log", "--pretty=format:%H%x00%an%x00%ae%x00%aI%x00%cI", "-n", "1000",
    )
    if result is None or result.returncode != 0:
        return []
    return result.stdout.strip().split('\n')


def analyze_commits(commits, repo_path):
    findings = []
    authors = {}
    now = datetime.datetime.now(datetime.timezone.utc)

    for line in commits:
        try:
            parts = line.split('\x00')
            if len(parts) < 5:
                continue

            commit_hash = parts[0][:12]
            author_name = parts[1]
            author_email = parts[2]
            author_date_str = parts[3]
            committer_date_str = parts[4]

            if author_email not in authors:
                authors[author_email] = set()
            authors[author_email].add(author_name)

            a_date = datetime.datetime.fromisoformat(author_date_str)
            c_date = datetime.datetime.fromisoformat(committer_date_str)

            # Future dates
            if a_date > now + datetime.timedelta(days=1):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Future Author Date",
                    description=f"Commit {commit_hash} has author date in the future",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author date: {author_date_str}",
                    category="time-anomaly"
                ))

            # Time stomping (>30 day lag)
            delta = c_date - a_date
            if delta > datetime.timedelta(days=30):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="medium",
                    title="Time Lag (>30 days)",
                    description="Large gap between author and committer dates",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author: {author_date_str}, Commit: {committer_date_str}",
                    category="time-anomaly"
                ))

            # Impossible time
            if delta < datetime.timedelta(0):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="high",
                    title="Impossible Time (Committer before Author)",
                    description="Committer date is before author date (time manipulation)",
                    file=f"commit:{commit_hash}", line=0,
                    snippet=f"Author: {author_date_str}, Commit: {committer_date_str}",
                    category="time-anomaly"
                ))

            # GPG signature status is intentionally not collected here: reading
            # it (%G?) makes git execute the repo's own gpg.program, an RCE
            # vector from an untrusted checkout, and the status is not a
            # trustworthy signal for a third-party repo anyway. See get_git_log.

        except (ValueError, IndexError):
            continue

    # Check for multiple names per email
    for email, names in authors.items():
        if len(names) > 2:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="medium",
                title="Multiple Identities per Email",
                description=f"Email '{email}' used by {len(names)} different author names",
                file="git-log", line=0,
                snippet=f"{email}: {', '.join(list(names)[:3])}",
                category="identity-anomaly"
            ))

    return findings


def scan_replace_refs(repo_path):
    """Detect git replace objects (refs/replace/*).

    Git replace objects silently rewrite what a commit hash resolves to,
    allowing an attacker to make a repo appear to have a clean history while
    serving a different object graph. This is a history-rewriting attack that
    bypasses normal git integrity checks unless --no-replace-objects is used.

    Detection: list any refs/replace/* refs via git for-each-ref. If any
    exist, report a critical finding.
    """
    findings = []
    result = core.run_git_hardened(repo_path, "for-each-ref", "refs/replace/")
    if result is None or result.returncode != 0:
        return findings
    output = result.stdout.strip()

    if output:
        ref_lines = [ln for ln in output.splitlines() if ln.strip()]
        ref_names = []
        for line in ref_lines:
            parts = line.split()
            if len(parts) >= 3:
                ref_names.append(parts[2])

        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="Git Replace Objects Detected",
            description=(
                f"Repository contains {len(ref_lines)} git replace object(s) under "
                f"refs/replace/. Replace objects silently rewrite commit/tree/blob "
                f"resolution, enabling history forgery that bypasses normal git log "
                f"output. Use 'git log --no-replace-objects' to see unmodified history."
            ),
            file=".git/refs/replace/",
            line=0,
            snippet=(', '.join(ref_names[:5]) + (' ...' if len(ref_names) > 5 else ''))[:120],
            category="git-history-tampering"
        ))

    return findings


def scan_grafts(repo_path):
    """Detect presence of .git/info/grafts file.

    Grafts are a deprecated git mechanism that rewrites the apparent parentage
    of commits, allowing an attacker to detach part of the history or introduce
    fake merge ancestry. While superseded by replace objects, grafts still work
    in all git versions and are rarely present in legitimate repositories.

    Detection: check if .git/info/grafts exists and is non-empty.
    """
    findings = []
    dot_git = os.path.join(repo_path, '.git')
    if os.path.isfile(dot_git):
        try:
            with open(dot_git, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
            if content.startswith('gitdir:'):
                dot_git = content[7:].strip()
                if not os.path.isabs(dot_git):
                    dot_git = os.path.join(repo_path, dot_git)
        except OSError:
            pass
    grafts_path = os.path.join(dot_git, 'info', 'grafts')

    if not os.path.isfile(grafts_path):
        return findings

    try:
        with open(grafts_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
    except OSError:
        return findings

    if not content:
        return findings

    lines = [ln for ln in content.splitlines() if ln.strip() and not ln.startswith('#')]
    if not lines:
        return findings

    findings.append(core.Finding(
        scanner=SCANNER_NAME, severity="high",
        title="Git Grafts File Detected",
        description=(
            f".git/info/grafts exists with {len(lines)} graft(s). Grafts rewrite "
            f"commit parentage, enabling history falsification and detached ancestry "
            f"attacks. Grafts are deprecated (superseded by replace objects) and "
            f"are rarely present in legitimate repositories."
        ),
        file=".git/info/grafts",
        line=0,
        snippet=lines[0][:120],
        category="git-history-tampering"
    ))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Git History Forensics")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Analyzing Git History in {repo_path}...")

    commits = get_git_log(repo_path)
    if not commits or commits == ['']:
        core.emit_status(args.format, "[-] No git history found or not a git repo.")
        core.output_findings([], args.format, SCANNER_NAME)
        return

    findings = analyze_commits(commits, repo_path)
    findings.extend(scan_replace_refs(repo_path))
    findings.extend(scan_grafts(repo_path))

    core.emit_status(args.format, f"[+] Analyzed {len(commits)} recent commits.")
    core.output_findings(findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
