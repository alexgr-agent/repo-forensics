#!/usr/bin/env python3
"""suppressions.py - persistent WARN-tier adjudication downgrades.

When the adjudicating agent downgrades a WARN-tier finding as benign in
context, it may record that decision here as a rejected-claim fingerprint:
(rule id, repo-relative file, SHA-256 of the file's content). Future scans
suppress an exact re-match instead of re-emitting the same standing WARN and
re-burning a host-agent adjudication on identical content.

Hard guards (the adjudication threat model is adversarial):
  * WARN tier only. BLOCK-tier findings and pre_scan.py blocks can NEVER be
    persisted away: the apply-side eligibility check refuses anything outside
    the WARN confidence band, so a stored record is inert the moment a finding
    escalates (e.g. a rule-pack update raises its confidence).
  * Any content edit re-fires. The fingerprint covers the file's full content,
    so a single changed byte produces a new fingerprint and the finding
    resurfaces for adjudication.
  * Always visible. Every report lists active suppressions with a one-command
    revoke.

Storage lives in the local history DB (scan_history.py); reads never create
it and storage failures never change scan output or exit codes.

CLI (for the adjudicating agent or the user):
  python3 suppressions.py add --repo <path> --file <relpath> --rule-id <id> --reason <text>
  python3 suppressions.py list
  python3 suppressions.py revoke --fingerprint <id-or-prefix>
  python3 suppressions.py revoke --all
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import stat
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scan_history  # noqa: E402

# Verdict-tier boundaries mirror aggregate_json / adjudication (locked KTD-7
# contract; kept local to avoid import cycles).
VERDICT_BLOCK_MIN = 0.92
VERDICT_WARN_MIN = 0.60

# Refuse to fingerprint files past this size. Scanner findings never point at
# files anywhere near this; the cap keeps `add` from hashing a multi-GB blob.
MAX_FILE_BYTES = 64 * 1024 * 1024

import re as _re

_CONTROL_CHARS_RE = _re.compile(
    "[" 
    "\x00-\x1f\x7f\x80-\x9f"   # C0/C1 controls
    "\u202a-\u202e\u2066-\u2069"  # bidi overrides + isolates
    "\u2060-\u2064\ufeff"          # zero-width / joiner controls
    "\x1b"                            # ESC (ANSI/OSC sequences)
    "]"
)


def _sanitize_reason(text: str, max_len: int = 300) -> str:
    """Strip control chars / ANSI / bidi / zero-widths from a stored reason so
    the report's suppression listing cannot carry terminal escapes or hidden
    text. Reuses adjudication.sanitize_snippet (full ANSI/CSI/OSC + orphan-SGR
    handling) with a local fallback when it is unavailable."""
    try:
        import adjudication
        return adjudication.sanitize_snippet(text, max_len=max_len)
    except (ImportError, AttributeError):
        cleaned = _CONTROL_CHARS_RE.sub("", text or "")
        cleaned = _re.sub(r"\s+", " ", cleaned).strip()
        return cleaned[:max_len]


def _normalize_relpath(relpath: str) -> str | None:
    """Normalize a repo-relative path to posix form; None when it escapes.

    Rejects absolute paths, drive-letter paths, empty paths, and any path
    containing a parent traversal after normalization.
    """
    if not isinstance(relpath, str) or not relpath.strip():
        return None
    rel = relpath.replace("\\", "/")
    if rel.startswith("/") or (len(rel) > 1 and rel[1] == ":"):
        return None
    parts = []
    for part in rel.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return "/".join(parts)


def fingerprint_for(repo_path: str, relpath: str, rule_id: str) -> str | None:
    """Compute the rejected-claim fingerprint for one finding location.

    Identity = (rule_id, normalized repo-relative path, SHA-256 of file
    content). Returns None when the file is missing, unreadable, not a regular
    file, too large, or resolves outside the repo (symlink escape) — a finding
    that cannot be fingerprinted can never be suppressed, so it simply
    re-fires next scan.
    """
    rel = _normalize_relpath(relpath)
    if rel is None or not isinstance(rule_id, str) or not rule_id:
        return None
    try:
        root = os.path.realpath(repo_path)
        target = os.path.realpath(os.path.join(root, rel))
        if target != root and not target.startswith(root + os.sep):
            return None
        st = os.stat(target)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            return None
        digest = hashlib.sha256()
        with open(target, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except (OSError, ValueError):
        return None
    return _fingerprint_from_parts(rel, rule_id, digest.hexdigest())


def _fingerprint_from_parts(rel: str, rule_id: str, content_hash: str) -> str:
    payload = {"file": rel, "rule_id": rule_id, "sha256": content_hash}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def fingerprint_and_hash(repo_path: str, relpath: str, rule_id: str):
    """Like fingerprint_for but also returns the raw content hash (for storage)."""
    rel = _normalize_relpath(relpath)
    if rel is None or not isinstance(rule_id, str) or not rule_id:
        return None
    try:
        root = os.path.realpath(repo_path)
        target = os.path.realpath(os.path.join(root, rel))
        if target != root and not target.startswith(root + os.sep):
            return None
        st = os.stat(target)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            return None
        digest = hashlib.sha256()
        with open(target, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except (OSError, ValueError):
        return None
    content_hash = digest.hexdigest()
    return _fingerprint_from_parts(rel, rule_id, content_hash), content_hash


PROMPT_INJECTION_PREFIXES = ("ST-PI-",)


def persist_command(finding) -> str | None:
    """Ready-to-run, shell-quoted persist command for one finding, or None.

    The file name comes from the scanned repo, so the reviewer must never
    compose this command by hand. Returns None when the finding can never be
    suppressed or when the path holds characters that would not survive
    display unchanged (then the fingerprint could not match anyway).
    """
    if not _finding_eligible(finding):
        return None
    raw_file = str(finding.get("file", ""))
    raw_rule = str(finding.get("rule_id", ""))
    if _normalize_relpath(raw_file) is None:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or not ch.isprintable() for ch in raw_file + raw_rule):
        return None
    return (
        f"{command_hint('add')} --repo <scanned-repo> --file {shlex.quote(raw_file)} "
        f"--rule-id {shlex.quote(raw_rule)} --reason '<why>'"
    )


def _finding_eligible(finding) -> bool:
    """Apply-side guard: ONLY WARN-tier, non-correlation findings with both a
    rule id and a file can ever be matched to a stored suppression."""
    if not isinstance(finding, dict):
        return False
    if finding.get("scanner") == "correlation":
        return False
    if not finding.get("rule_id") or not finding.get("file"):
        return False
    # Exit code is severity-driven while the tier is confidence-driven, and
    # many critical rules sit in the WARN confidence band. A critical finding
    # must never be silenced, and a prompt-injection snippet is by definition
    # text trying to talk the reviewer into a benign verdict.
    if str(finding.get("severity", "")).lower() == "critical":
        return False
    if str(finding.get("rule_id", "")).upper().startswith(PROMPT_INJECTION_PREFIXES):
        return False
    try:
        confidence = float(finding.get("confidence"))
    except (TypeError, ValueError):
        return False
    return VERDICT_WARN_MIN <= confidence < VERDICT_BLOCK_MIN


def partition_suppressed(findings, repo_path, records):
    """Split findings into (active, adjudication-suppressed).

    A finding is suppressed only when it is WARN-tier eligible AND its freshly
    computed fingerprint matches a stored record — so identical rule+file with
    edited content (different content hash) stays active and re-fires.
    Suppressed findings lose needs_adjudication and gain audit metadata.
    """
    if not records:
        return list(findings), []
    index = {record["fingerprint"]: record for record in records}
    fingerprint_cache = {}
    active, suppressed = [], []
    for finding in findings:
        record = None
        if _finding_eligible(finding):
            key = (finding.get("file", ""), finding.get("rule_id", ""))
            if key not in fingerprint_cache:
                fingerprint_cache[key] = fingerprint_for(
                    repo_path, finding.get("file", ""), finding.get("rule_id", "")
                )
            fingerprint = fingerprint_cache[key]
            if fingerprint:
                record = index.get(fingerprint)
            if record is not None:
                annotated = dict(finding)
                annotated.pop("needs_adjudication", None)
                annotated["suppression_source"] = "adjudication"
                annotated["suppression"] = {
                    "fingerprint": fingerprint,
                    "rule_id": record["rule_id"],
                    "reason": record["reason"],
                    "created_at": record["created_at"],
                }
                suppressed.append(annotated)
                continue
        active.append(finding)
    return active, suppressed


def load_active_records(db_path: str | None = None) -> list[dict]:
    """Failure-safe read of all active suppression records (never creates the DB)."""
    return scan_history.load_suppressions_safely(db_path)


def record_applies_to_repo(record: dict, repo_path: str) -> bool:
    """True when the record's file exists inside repo_path (any content)."""
    rel = _normalize_relpath(str(record.get("relpath", "")))
    if rel is None:
        return False
    try:
        root = os.path.realpath(repo_path)
        target = os.path.realpath(os.path.join(root, rel))
    except (OSError, ValueError):
        return False
    return target.startswith(root + os.sep) and os.path.isfile(target)


def summarize_record(record: dict) -> dict:
    """Compact, JSON-safe view of one record for report embedding."""
    return {
        "fingerprint": record["fingerprint"],
        "rule_id": record["rule_id"],
        "file": record["relpath"],
        "reason": record["reason"],
        "created_at": record["created_at"],
    }


def command_hint(*args: str) -> str:
    """Absolute invocation string for this script, for report embedding."""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suppressions.py")
    return " ".join([f'python3 "{script}"', *args])


# --- CLI -----------------------------------------------------------------

def _cli_add(args) -> int:
    repo = os.path.realpath(args.repo)
    if not os.path.isdir(repo):
        print(f"[!] --repo is not a directory: {args.repo}", file=sys.stderr)
        return 2
    rel = _normalize_relpath(args.file)
    if rel is None:
        print(f"[!] --file must be a repo-relative path: {args.file!r}", file=sys.stderr)
        return 2
    reason = _sanitize_reason(args.reason)
    if not reason:
        print("[!] --reason is required (a downgrade without a reason is not auditable)",
              file=sys.stderr)
        return 2
    parts = fingerprint_and_hash(repo, rel, args.rule_id)
    if parts is None:
        print(f"[!] cannot fingerprint {rel}: missing, unreadable, not a regular "
              f"file, too large, or outside the repo", file=sys.stderr)
        return 2
    fingerprint, content_hash = parts
    result = scan_history.add_suppression_safely(
        fingerprint, args.rule_id, rel, content_hash, reason
    )
    if result is None:
        return 3
    print(f"suppressed {fingerprint[:12]}  {args.rule_id}  {rel}")
    print("applies to WARN-tier re-matches with byte-identical content; "
          "any edit re-fires the finding.")
    return 0


def _cli_list(args) -> int:
    records = load_active_records()
    if args.json:
        json.dump([summarize_record(r) for r in records], sys.stdout, indent=2,
                  sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if not records:
        print("no active adjudication suppressions")
        return 0
    print(f"{len(records)} active adjudication suppression(s):")
    for record in records:
        stamp = time.strftime("%Y-%m-%d", time.localtime(record["created_at"]))
        rule_id = _sanitize_reason(str(record["rule_id"]), max_len=80)
        relpath = _sanitize_reason(str(record["relpath"]), max_len=160)
        reason = _sanitize_reason(str(record["reason"]), max_len=300)
        print(f"  {record['fingerprint'][:12]}  {rule_id}  {relpath}")
        print(f"      reason: {reason}  (recorded {stamp})")
    print(f"revoke one: {command_hint('revoke', '--fingerprint', '<id>')}")
    print(f"revoke all: {command_hint('revoke', '--all')}")
    return 0


def _cli_revoke(args) -> int:
    path = scan_history.suppressions_db_path()
    if not os.path.isfile(path):
        print("no active adjudication suppressions")
        return 0
    try:
        store = scan_history.HistoryStore(path)
        if args.all:
            removed = store.clear_suppressions()
            print(f"revoked {removed} suppression(s)")
            return 0
        removed = store.revoke_suppression(args.fingerprint)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # storage failure: clean message, no traceback
        print(f"[!] could not revoke: {exc}", file=sys.stderr)
        return 3
    if removed:
        print(f"revoked {removed} suppression(s)")
    else:
        print(f"[!] no suppression matches {args.fingerprint!r}", file=sys.stderr)
        return 2
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Manage persistent WARN-tier adjudication suppressions."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="record a downgrade for exact re-matches")
    p_add.add_argument("--repo", required=True, help="scanned repository root")
    p_add.add_argument("--file", required=True, help="repo-relative file path")
    p_add.add_argument("--rule-id", required=True, help="rule id from the finding")
    p_add.add_argument("--reason", required=True, help="why the finding is benign")
    p_add.set_defaults(func=_cli_add)

    p_list = sub.add_parser("list", help="list active suppressions")
    p_list.add_argument("--json", action="store_true", help="machine-readable output")
    p_list.set_defaults(func=_cli_list)

    p_revoke = sub.add_parser("revoke", help="remove suppressions")
    group = p_revoke.add_mutually_exclusive_group(required=True)
    group.add_argument("--fingerprint", help="fingerprint or unique prefix")
    group.add_argument("--all", action="store_true", help="revoke every suppression")
    p_revoke.set_defaults(func=_cli_revoke)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
