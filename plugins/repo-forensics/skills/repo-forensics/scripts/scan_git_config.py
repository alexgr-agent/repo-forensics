#!/usr/bin/env python3
"""
scan_git_config.py - Executable Git Configuration / Shipped-.git Scanner

Detects the executable-git-config attack class (the "Beltdown" family): agent
CLIs and humans run git inside a workspace, and git executes values taken from
repository-supplied configuration. A .git directory that arrives inside
scanned content - nested in a checkout, planted by a runtime rename or copy,
or packed into an archive - can therefore execute commands with the victim's
authority, outside any sandbox the agent applied to its own shell tool.

Detection surface:

1. Shipped .git directories. Version-control tooling never distributes its
   metadata directory, so a .git directory anywhere except the scanned
   checkout's own root is hostile by construction. On the filesystem a nested
   .git is reported on presence (high); inside an archive it is critical.
2. Armed executable config keys. .git/config carrying command-executing keys
   (core.fsmonitor, core.hooksPath, core.sshCommand, core.pager, core.editor,
   core.askpass, filter.<name>.clean/smudge/process, gpg.program,
   diff.external, shell aliases, include/includeIf paths, credential.helper)
   with values that actually run something. Protective values (false,
   /dev/null, empty, the built-in credential helpers, git-lfs filter commands,
   the default gpg binaries) are inert and never flagged. Shipped configs are
   critical; the scanned checkout's own root config is high (local tools
   legitimately set some of these - for the root rule, core.pager/core.editor
   only fire on path-like values, so `editor = vim` in a developer's own
   checkout stays silent).
3. gitdir: pointer files (.git as a file). Legitimate submodule/worktree
   pointers resolve inside the scanned tree's own .git; anything else is a
   planted indirection. A pointer at the scanned ROOT gets the worktree-safe
   treatment: it stays silent only when the target directory proves the
   bidirectional link git maintains for real worktrees (commondir file plus a
   gitdir back-pointer resolving to the scanned root's own .git file); a root
   pointer escaping the tree without that proof, or arming content shipped
   inside the tree, is flagged.
4. .gitmodules with `update = !command` - arbitrary shell execution on
   `git submodule update`.
5. Staged plant chain: a single file (code or prose) that writes an
   exec-capable git config key AND renames or copies a directory to `.git` -
   the runtime plant that turns a clean clone into an armed one after
   scanning. Matching is not regex-only: the target must be exactly `.git`
   (basename), and common one-hop indirection (`target=.git` then
   `mv stage "$target"`, `target='.git'` then `os.rename(stage, target)`) is
   resolved for shell, cmd, PowerShell, Python and Node.

Design notes (the asymmetries a reviewer will ask about):

- Filesystem-HIGH vs archive-CRITICAL for shipped-.git presence. On the
  filesystem a nested .git is HIGH: rare-but-real developer layouts (a repo
  accidentally nested inside another checkout) exist, and the scanner cannot
  prove the content was *distributed*. A distribution archive is different:
  no legitimate packaging pipeline emits .git metadata, so presence alone is
  CRITICAL there. Armed config/hook CONTENT is critical on both surfaces.
- Ignored dependency roots (node_modules, venv, dist, ...) are skipped for
  ordinary content by every scanner, but NOT for .git metadata: a planted
  node_modules/<pkg>/.git is a prime hiding spot, so the filesystem pass
  sweeps ignored roots for .git directories/pointer files only. This mirrors
  the archive path, which classifies every member path including ones under
  ignored-looking directories.
- Hook recognition: only real git hook names (pre-commit, post-checkout,
  fsmonitor-watchman, ...) count as shipped hooks, and the .sample exclusion
  is case-insensitive. Arbitrary files under hooks/ (README, notes) are not
  hooks; the nested .git itself is still reported on presence.
- The rename/copy plant arm resolves variables FLOW-SENSITIVELY: the last
  assignment before each use wins and assignments after a use do not arm it,
  so `target=.git` followed by `target=backup` stays silent. The cheap
  indirection classes resolve too (multi-hop variables, quote-concatenation,
  $(printf/echo ...) constants, backslash escapes, '.'+'git' concatenation,
  Node template constants), and target comparison is case-insensitive
  (.GIT IS git's directory on Windows/macOS). Deeper dataflow (functions,
  loops, non-constant substitutions) is a documented limitation: it
  resolves to unknown and arms nothing.

Cross-platform: all checks are content- and path-shape-based; shell, cmd,
PowerShell, Python and Node rename/copy idioms are covered. No git subprocess
is spawned against scanned content.

Created by Alex Greenshpun
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "git_config"

# Rule ids (registered in data/rule_ids.csv).
R_SHIPPED_DIR = "GC-SHIP-001"      # nested .git directory on the filesystem
R_ARMED_CONFIG = "GC-SHIP-002"     # armed exec key in a shipped .git/config
R_ARCHIVE_GIT = "GC-SHIP-003"      # archive member under a .git/ path
R_GITDIR_PTR = "GC-SHIP-004"       # hostile gitdir: pointer file
R_SHIPPED_HOOKS = "GC-SHIP-005"    # non-sample hook file in a shipped .git
R_ROOT_CONFIG = "GC-ROOT-001"      # armed exec key in the checkout's own config
R_GITMODULES_EXEC = "GC-MOD-001"   # .gitmodules update = !command
R_RENAME_CHAIN = "GC-REN-001"      # config write + rename/copy-to-.git in one file

# Whole-scanner wall-clock budget, matching the pipeline timeout discipline of
# the other walk_aux-style scanners (the hook runner SIGKILLs at 15s).
TOTAL_BUDGET_SEC = 12
# Per-file read cap for the plant-chain rule; chain scripts are small.
_CHAIN_READ_BYTES = 2 * 1024 * 1024
# Cap on shipped-.git presence findings per scan (pathological trees).
_MAX_SHIPPED_DIR_FINDINGS = 50
# Cap on shipped-hook findings per scan - shared by the filesystem and
# archive paths so neither can flood the report from a hook farm.
_MAX_HOOK_FINDINGS = 5
# Cap on armed-config findings per parsed config body.
_MAX_ARMED_CONFIG_FINDINGS = 25


# ---------------------------------------------------------------------------
# Tolerant git-config (INI) parsing
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r'^\s*\[\s*([A-Za-z0-9_.-]+)(?:\s+"([^"]*)")?\s*\]')
_KV_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9.-]*)\s*(?:=\s*(.*))?$')

# core.fsmonitor values that do NOT execute an external command: empty/unset,
# booleans (the boolean values select git's built-in fsmonitor, no exec).
_FSMONITOR_INERT = {"", "true", "false", "yes", "no", "on", "off", "0", "1"}
# core.hooksPath values that disable hooks rather than redirect them.
_HOOKSPATH_INERT = {"", "/dev/null", "nul"}
# credential.helper values backed by git's own helpers (no attacker binary).
_SAFE_CREDENTIAL_HELPERS = {
    "cache", "store", "manager", "manager-core", "manager-xdg", "osxkeychain",
    "wincred", "libsecret", "pass", "keepassxc", "netrc",
}
# gpg.program values naming the stock binaries git would exec anyway.
_GPG_PROGRAM_INERT = {"", "gpg", "gpg2"}
# filter.<name>.* values driven by git-lfs' own local install; the stock LFS
# filter commands are not attacker-controlled. The name requires a word
# boundary (whitespace or end-of-value): `git-lfs-evil` and `git-lfsmuggle`
# are attacker binaries, not git-lfs.
_FILTER_LFS_INERT_RE = re.compile(r"git-lfs(?:\s|$)", re.IGNORECASE)


def _strip_comment(value):
    """Remove a trailing git-config comment (unquoted # or ;)."""
    out = []
    in_quote = False
    for i, ch in enumerate(value):
        if ch == '"' and (i == 0 or value[i - 1] != "\\"):
            in_quote = not in_quote
        if ch in "#;" and not in_quote and (i == 0 or value[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).strip()


def _unquote(value):
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _parse_config(text):
    """Yield (section, subsection, key, value, line_no, line_text) entries."""
    section = ""
    subsection = ""
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1).lower()
            subsection = m.group(2) or ""
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key = m.group(1).lower()
        value = _unquote(_strip_comment(m.group(2) or ""))
        yield section, subsection, key, value, line_no, raw.strip()


def _credential_helper_armed(value):
    if not value:
        return False
    if value.startswith("!"):
        return True  # shell command, always exec
    first = value.split()[0].lower()
    if first in _SAFE_CREDENTIAL_HELPERS:
        return False
    # A bare unknown helper name resolves to a `git-credential-<name>` binary
    # on PATH; a path value runs that exact file. Both execute attacker-supplied
    # code when the helper ships next to the config.
    return True


def _looks_path_like(value):
    """A pager/editor value that names a specific file rather than a PATH
    program: `editor = vim` is a developer preference, `editor = ./evil` or
    `editor = /tmp/evil` executes a particular binary."""
    return ("/" in value or "\\" in value
            or value.startswith(("~", ".")))


def armed_config_entries(config_text, root=False):
    """Return exec-capable config entries whose values actually run something.

    Each entry is dict(key, value, line, line_text, reason). Protective values
    used by sandbox hardening guides (fsmonitor=false, hooksPath=/dev/null) are
    deliberately inert so hardened repos never trip the rule.

    root=True applies the scanned-checkout's-own-config leniency: core.pager
    and core.editor only count when the value is path-like, because developers
    legitimately set them to PATH program names (vim, less, code) in their own
    checkouts. Shipped configs get no such benefit - every value is hostile.
    """
    armed = []
    for section, _sub, key, value, line_no, line_text in _parse_config(config_text):
        reason = None
        fqkey = f"{section}.{key}" if section else key
        if section == "core" and key == "fsmonitor":
            if value.lower() not in _FSMONITOR_INERT:
                reason = "git executes the fsmonitor hook on working-tree queries"
        elif section == "core" and key == "hookspath":
            if value.strip().lower() not in _HOOKSPATH_INERT:
                reason = "git executes hooks from this directory on ordinary git operations"
        elif section == "core" and key in ("sshcommand",):
            if value:
                reason = f"git executes core.{key} as a shell command"
        elif section == "core" and key in ("pager", "editor"):
            if value and not (root and not _looks_path_like(value)):
                reason = f"git executes core.{key} as a shell command"
        elif section == "core" and key == "askpass":
            if value:
                reason = "git executes core.askpass to obtain credentials"
        elif section == "gpg" and key == "program":
            if value.strip().lower() not in _GPG_PROGRAM_INERT:
                reason = "git executes gpg.program for signing operations"
        elif section == "diff" and key == "external":
            if value:
                reason = "git executes diff.external as the diff driver"
        elif section == "filter" and key in ("clean", "smudge", "process"):
            if value and not _FILTER_LFS_INERT_RE.match(value.lstrip()):
                reason = (f"git runs the filter.{key} command on checkout/"
                          f"checkin of every matching path (.gitattributes)")
        elif section == "alias":
            if value.lstrip().startswith("!"):
                reason = f"shell alias `git {key}` executes an arbitrary command"
        elif section in ("include", "includeif") and key == "path":
            if value:
                reason = "pulls additional config, which can carry the keys above, from this path"
        elif section.startswith("credential") and key == "helper":
            if _credential_helper_armed(value):
                reason = "git executes the credential helper on authentication"
        if reason:
            armed.append({
                "key": fqkey, "value": value, "line": line_no,
                "line_text": line_text[:120], "reason": reason,
            })
    return armed


def _config_findings(config_text, file_label, *, rule_id, severity, shipped,
                     line_numbers=True):
    """One finding per armed exec key in a .git/config body, capped so a
    pathological config cannot flood the report."""
    findings = []
    entries = armed_config_entries(config_text, root=not shipped)
    for entry in entries[:_MAX_ARMED_CONFIG_FINDINGS]:
        where = "shipped .git/config" if shipped else "the scanned checkout's own .git/config"
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity=severity, rule_id=rule_id,
            title=f"Executable git config key armed: {entry['key']}",
            description=(
                f"{where} sets `{entry['key']} = {entry['value']}': "
                f"{entry['reason']}. Any git command run in this workspace "
                f"(including an agent CLI's own background git) executes it."
            ),
            file=file_label, line=entry["line"] if line_numbers else 0,
            snippet=entry["line_text"], category="git-config-exec",
            evidence_class="direct",
        ))
    return findings


# ---------------------------------------------------------------------------
# gitdir: pointer files (.git as a regular file)
# ---------------------------------------------------------------------------

# re.M: a pointer file's gitdir line must be found even when the file carries
# trailing content; without it the $ anchor only matched a single-line file.
_GITDIR_RE = re.compile(r"^\s*gitdir\s*:\s*(?P<target>.+?)\s*$",
                        re.IGNORECASE | re.MULTILINE)


def _read_gitdir_target(pointer_path):
    try:
        with open(pointer_path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    m = _GITDIR_RE.search(head)
    return m.group("target") if m else None


def _is_within(path, root):
    try:
        return os.path.commonpath([os.path.normcase(os.path.abspath(path)),
                                   os.path.normcase(os.path.abspath(root))]) == \
            os.path.normcase(os.path.abspath(root))
    except ValueError:  # different drives (Windows)
        return False


def _norm(path):
    """Case-normalised, redundant-separator-free path for comparisons
    (normcase matters on Windows, where one directory spells several ways)."""
    return os.path.normcase(os.path.normpath(path))


def _verify_worktree_link(resolved_target, pointer_fs):
    """Worktree-safe check for a ROOT .git pointer file.

    Git maintains a bidirectional link for real worktrees, and every half of
    it is validated here because each file is individually forgeable:

    - the target dir holds a `commondir` file whose CONTENTS resolve to a
      genuine main repository gitdir (a directory containing HEAD);
    - the target sits at exactly <main-gitdir>/worktrees/<name> - git never
      writes worktree metadata anywhere else;
    - the target's `gitdir` back-pointer resolves back to this worktree's
      own .git pointer file.

    Anything less is a planted indirection: a manufactured directory
    carrying a `commondir` file (contents ".") plus a back-pointer is not
    proof, and real git will happily execute the armed external config."""
    try:
        if not os.path.isdir(resolved_target):
            return False
        commondir_file = os.path.join(resolved_target, "commondir")
        back_pointer = os.path.join(resolved_target, "gitdir")
        if not os.path.isfile(commondir_file):
            return False
        if not os.path.isfile(back_pointer):
            return False
        with open(commondir_file, "r", encoding="utf-8",
                  errors="replace") as fh:
            common_rel = fh.read(4096).strip()
        with open(back_pointer, "r", encoding="utf-8",
                  errors="replace") as fh:
            back_target = fh.read(4096).strip()
    except OSError:
        return False
    if not common_rel or not back_target:
        return False
    if os.path.isabs(common_rel):
        main_gitdir = os.path.normpath(common_rel)
    else:
        main_gitdir = os.path.normpath(
            os.path.join(resolved_target, common_rel))
    # Topology: the worktree gitdir must sit directly under the main repo's
    # .git/worktrees/, and the commondir target must be a real gitdir.
    if _norm(os.path.dirname(resolved_target)) != \
            _norm(os.path.join(main_gitdir, "worktrees")):
        return False
    if not os.path.isfile(os.path.join(main_gitdir, "HEAD")):
        return False
    if not os.path.isabs(back_target):
        back_target = os.path.join(resolved_target, back_target)
    return _norm(back_target) == _norm(pointer_fs)


def _genuine_gitdir(path):
    """A directory git maintains as repository metadata: HEAD plus object
    and ref stores. A manufactured lookalike must reproduce all three."""
    return (os.path.isfile(os.path.join(path, "HEAD"))
            and os.path.isdir(os.path.join(path, "objects"))
            and os.path.isdir(os.path.join(path, "refs")))


def _proven_worktree_checkout(main_gitdir, wt_meta):
    """The checkout path of a linked worktree, or None when <wt_meta> does
    not prove git's bidirectional link against <main_gitdir>: the
    worktree's `commondir` contents must resolve to the genuine main
    gitdir, and its `gitdir` file names the checkout's own .git pointer."""
    try:
        with open(os.path.join(wt_meta, "commondir"), "r",
                  encoding="utf-8", errors="replace") as fh:
            common_rel = fh.read(4096).strip()
        with open(os.path.join(wt_meta, "gitdir"), "r",
                  encoding="utf-8", errors="replace") as fh:
            back_target = fh.read(4096).strip()
    except OSError:
        return None
    if not common_rel or not back_target:
        return None
    if os.path.isabs(common_rel):
        common = os.path.normpath(common_rel)
    else:
        common = os.path.normpath(os.path.join(wt_meta, common_rel))
    if _norm(common) != _norm(main_gitdir):
        return None
    if not os.path.isabs(back_target):
        back_target = os.path.join(wt_meta, back_target)
    # The back-pointer names <checkout>/.git; the checkout is its dirname.
    return os.path.dirname(os.path.normpath(back_target))


def _verify_submodule_link(resolved_target, pointer_fs):
    """Submodule-safe check for a ROOT .git pointer file. A submodule
    checkout scanned as the scan root has a root pointer whose target is
    the submodule gitdir inside the PARENT repository's .git/modules/ tree.
    Proof mirrors the worktree check - genuine parent-repository topology,
    never a path substring or a planted back-link:

    - the target is a real git metadata dir (HEAD/objects/refs). Real git
      (verified 2.34.1) writes NO `gitdir` back-pointer there, so requiring
      one flags every genuine submodule, and accepting one as proof
      authenticates a plant: a manufactured directory at a path containing
      `.git/modules` carrying an attacker-written back-pointer is exactly
      the demonstrated bypass this check exists to reject;
    - the target sits under <parent-gitdir>/modules/<name> (nested
      submodules repeat modules/<name>; a submodule of a linked worktree
      sits under <parent-gitdir>/worktrees/<wt>/modules/<name> and the
      worktree half must prove its own bidirectional link), where
      <parent-gitdir> is a directory named .git that is itself genuine
      (HEAD/objects/refs);
    - the parent checkout contains the scan root: the pointer's escape
      lands in the checkout's own ancestry, not in an unrelated directory
      the attacker shaped to look like a parent.
    """
    try:
        if not os.path.isdir(resolved_target):
            return False
        if not _genuine_gitdir(resolved_target):
            return False
        parts = os.path.normpath(resolved_target).split(os.sep)
        scan_root = os.path.dirname(os.path.abspath(pointer_fs))
        for i in range(len(parts) - 3, -1, -1):
            if parts[i].lower() != ".git":
                continue
            parent_gitdir = os.sep.join(parts[:i + 1])
            tail = [p.lower() for p in parts[i + 1:]]
            if len(tail) >= 4 and tail[0] == "worktrees":
                wt_meta = os.path.join(parent_gitdir, "worktrees",
                                       parts[i + 2])
                checkout = _proven_worktree_checkout(parent_gitdir, wt_meta)
                rest = tail[2:]
            elif tail[0] == "modules":
                checkout = os.path.dirname(parent_gitdir)
                rest = tail
            else:
                continue
            if checkout is None:
                continue
            # After the leading `modules`, the submodule's own PATH becomes
            # the directory name - slashes included (a submodule at
            # vendor/oniguruma lives at .git/modules/vendor/oniguruma), and
            # nested submodules repeat /modules/ deeper. The genuineness
            # checks (real target gitdir, real parent gitdir, scan root
            # inside the parent checkout) carry the proof, so the shape
            # requirement is only: starts with modules, at least one
            # component deep, no empty components.
            if len(rest) < 2 or any(not c for c in rest):
                continue
            if not _genuine_gitdir(parent_gitdir):
                continue
            if _norm(scan_root) != _norm(checkout) and \
                    _is_within(scan_root, checkout):
                return True
        return False
    except OSError:
        return False


def _verified_link_config_findings(resolved_target):
    """Config + hooks check for a proven worktree/submodule gitdir target.
    The target is the user's own outer-checkout machinery, so the
    root-config leniency applies (core.pager/core.editor only fire on
    path-like values) - but any other armed exec key, and any executable
    hook in the target's hooks/ directory, still runs with the victim's
    authority and must fire even behind valid topology."""
    findings = []
    config_path = os.path.join(resolved_target, "config")
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8",
                      errors="replace") as fh:
                config_text = fh.read(1024 * 1024)
        except OSError:
            config_text = ""
        findings.extend(_config_findings(config_text, config_path,
                                         rule_id=R_ROOT_CONFIG,
                                         severity="high", shipped=False))
    hooks_dir = os.path.join(resolved_target, "hooks")
    try:
        hook_names = sorted(os.listdir(hooks_dir))
    except OSError:
        hook_names = []
    count = 0
    for name in hook_names:
        if count >= _MAX_HOOK_FINDINGS:
            break
        if _hook_name_or_none(name) is None:
            continue
        if os.path.isfile(os.path.join(hooks_dir, name)):
            count += 1
            findings.append(_shipped_hooks_finding(
                os.path.join(hooks_dir, name)))
    return findings


# ---------------------------------------------------------------------------
# Filesystem scan
# ---------------------------------------------------------------------------

def _shipped_dir_finding(rel_path, via):
    return core.Finding(
        scanner=SCANNER_NAME, severity="high", rule_id=R_SHIPPED_DIR,
        title="Shipped .git directory in scanned content",
        description=(
            f"A git metadata directory is present at {rel_path} ({via}). "
            f"Version-control tooling never distributes its .git directory, so "
            f"one arriving inside scanned content was planted; its config and "
            f"hooks execute commands on ordinary git operations."
        ),
        file=rel_path, line=0, snippet=".git/",
        category="shipped-git-dir", evidence_class="direct",
    )


def _shipped_hooks_finding(rel_path):
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical", rule_id=R_SHIPPED_HOOKS,
        title="Executable hook shipped inside .git/hooks",
        description=(
            f"{rel_path} is a non-sample git hook shipped with the content. "
            f"Git executes it on the matching operation (commit, checkout, "
            f"push, ...) with the victim's authority."
        ),
        file=rel_path, line=0, snippet=os.path.basename(rel_path),
        category="git-config-exec", evidence_class="direct",
    )


def _gitdir_pointer_finding(rel_path, target, reason):
    return core.Finding(
        scanner=SCANNER_NAME, severity="high", rule_id=R_GITDIR_PTR,
        title="gitdir pointer file redirects git metadata",
        description=(
            f"{rel_path} is a `.git` pointer file redirecting the git "
            f"directory to {target}: {reason}. Legitimate submodule/worktree "
            f"pointers resolve inside the scanned tree's own .git directory "
            f"(a root worktree pointer must also prove git's bidirectional "
            f"commondir/gitdir link)."
        ),
        file=rel_path, line=0, snippet=f"gitdir: {target}"[:120],
        category="shipped-git-dir", evidence_class="direct",
    )


# The hook names git executes (git help hooks), compared lower-cased. Only
# these count as shipped hooks: an arbitrary file under hooks/ (a README, a
# note) is not executable by git, while the .sample exclusion must be
# case-insensitive (pre-commit.SAMPLE is as inert as pre-commit.sample).
_KNOWN_HOOKS = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch",
    "pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg",
    "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push",
    "pre-receive", "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc",
    "post-rewrite", "sendemail-validate", "fsmonitor-watchman",
    "p4-changelist", "p4-prepare-changelist", "p4-post-changelist",
    "p4-pre-submit", "post-index-change",
})


def _hook_name_or_none(name):
    n = name.lower()
    if n.endswith(".sample"):
        return None
    return n if n in _KNOWN_HOOKS else None


def _scan_git_dir(git_fs_path, git_rel_path, findings, state):
    """Parse a shipped .git directory: armed config + recognized non-sample
    hooks (both capped)."""
    config_path = os.path.join(git_fs_path, "config")
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8", errors="replace") as fh:
                config_text = fh.read(1024 * 1024)
        except OSError:
            config_text = ""
        findings.extend(_config_findings(
            config_text, os.path.join(git_rel_path, "config"),
            rule_id=R_ARMED_CONFIG, severity="critical", shipped=True))
    hooks_dir = os.path.join(git_fs_path, "hooks")
    try:
        hook_names = sorted(os.listdir(hooks_dir))
    except OSError:
        hook_names = []
    for name in hook_names:
        if _hook_name_or_none(name) is None:
            continue
        if state["hooks"] >= _MAX_HOOK_FINDINGS:
            break
        hook_path = os.path.join(hooks_dir, name)
        if os.path.isfile(hook_path):
            state["hooks"] += 1
            findings.append(_shipped_hooks_finding(
                os.path.join(git_rel_path, "hooks", name)))


def _scan_nested_gitdir_file(pointer_fs, pointer_rel, repo_path, findings,
                             state):
    """A `.git` FILE below the root: legitimate only as submodule/worktree
    machinery pointing back into the root's own .git directory."""
    target = _read_gitdir_target(pointer_fs)
    if target is None:
        return
    resolved = target if os.path.isabs(target) else os.path.join(
        os.path.dirname(pointer_fs), target)
    resolved = os.path.normpath(resolved)
    own_git = os.path.join(os.path.abspath(repo_path), ".git")
    if _is_within(resolved, own_git):
        return  # submodule/worktree machinery of the checkout itself
    if not _is_within(resolved, repo_path):
        findings.append(_gitdir_pointer_finding(
            pointer_rel, target, "it resolves OUTSIDE the scanned tree"))
        return
    # Points at a directory inside the tree that is not the checkout's own
    # .git: shipped git machinery behind a pointer.
    findings.append(_gitdir_pointer_finding(
        pointer_rel, target, "it arms git metadata shipped inside the content"))
    if os.path.isdir(resolved):
        _scan_git_dir(resolved, os.path.normpath(os.path.join(
            os.path.dirname(pointer_rel), target)), findings, state)


def _scan_root_gitdir_file(pointer_fs, repo_abs, findings, state):
    """The scanned checkout's own root `.git` as a FILE. Real worktree roots
    point outside the tree AND prove git's bidirectional commondir/gitdir
    link against a genuine main-repo topology; real submodule checkouts
    point under the parent's .git/modules/ and prove genuine parent
    topology (a real modules/<name> gitdir inside a real parent
    repository that contains the scan root). Anything
    else (an escaping pointer without that proof, or a pointer arming
    content shipped inside the tree) is a planted indirection."""
    target = _read_gitdir_target(pointer_fs)
    if target is None:
        return  # not a gitdir pointer at all; nothing to arm
    resolved = target if os.path.isabs(target) else os.path.join(
        os.path.dirname(pointer_fs), target)
    resolved = os.path.normpath(resolved)
    if _is_within(resolved, repo_abs):
        # A root worktree pointer never resolves inside its own tree: git
        # writes <main-checkout>/.git/worktrees/<name>, which is outside the
        # worktree being scanned. Resolving inside means the pointer arms
        # metadata shipped with the content.
        findings.append(_gitdir_pointer_finding(
            ".git", target, "a ROOT pointer arming git metadata shipped "
            "inside the content"))
        if os.path.isdir(resolved):
            _scan_git_dir(resolved, os.path.normpath(target), findings, state)
        return
    if _verify_worktree_link(resolved, pointer_fs) or \
            _verify_submodule_link(resolved, pointer_fs):
        # Proven worktree/submodule machinery stays silent on presence - but
        # an armed config inside the target still executes, so it is
        # inspected (with the root-config leniency) before suppressing.
        findings.extend(_verified_link_config_findings(resolved))
        return
    findings.append(_gitdir_pointer_finding(
        ".git", target, "a ROOT pointer escaping the scanned tree without "
        "worktree/submodule proof (no genuine commondir/gitdir back-link "
        "topology)"))


def _shipped_git_at(git_fs, git_rel, findings, state):
    """Presence finding + content scan for one discovered shipped .git dir
    (capped). Symlinked .git directories are resolved and their targets
    inspected - a link is not a hiding place."""
    if state["shipped"] >= _MAX_SHIPPED_DIR_FINDINGS:
        return
    state["shipped"] += 1
    findings.append(_shipped_dir_finding(git_rel, "filesystem"))
    scan_fs = os.path.realpath(git_fs) if os.path.islink(git_fs) else git_fs
    if os.path.isdir(scan_fs):
        _scan_git_dir(scan_fs, git_rel, findings, state)


def _sweep_ignored_root(fs_path, rel_path, repo_abs, findings, deadline, state):
    """Ignored dependency roots (node_modules, venv, dist, ...) stay ignored
    for ordinary content, but a planted .git inside them must still surface:
    sweep the subtree for git metadata only. Mirrors the archive path, which
    classifies every member path."""
    for root, dirs, files in os.walk(fs_path, followlinks=False):
        if time.monotonic() > deadline:
            state["incomplete"] = True
            return
        rel_root = os.path.relpath(root, repo_abs)
        kept = []
        for d in dirs:
            if d.lower() == ".git":
                git_fs = os.path.join(root, d)
                git_rel = os.path.normpath(os.path.join(rel_root, d))
                _shipped_git_at(git_fs, git_rel, findings, state)
                continue  # never descend into any .git directory
            kept.append(d)
        dirs[:] = kept
        for f in files:
            if f.lower() != ".git":
                continue
            pointer_fs = os.path.join(root, f)
            _scan_nested_gitdir_file(
                pointer_fs, os.path.normpath(os.path.join(rel_root, f)),
                repo_abs, findings, state)


def _walk_shipped_git(repo_path, findings, deadline):
    """Filesystem pass: nested .git directories (including inside ignored
    dependency roots), gitdir pointer files, and the scanned checkout's own
    root config / root pointer / root symlink. A root .git DIRECTORY is the
    checkout's own machinery, so it is never reported on presence and never
    descended into; a root .git SYMLINK is machinery git never creates, so
    it is reported and its realpath target inspected."""
    repo_abs = os.path.abspath(repo_path)
    state = {"shipped": 0, "hooks": 0, "incomplete": False}

    root_dotgit = os.path.join(repo_abs, ".git")
    if os.path.islink(root_dotgit):
        # The checkout's own .git as a SYMLINK: git never creates one (root
        # redirects are pointer FILES), so this is a planted indirection -
        # and a silently invisible one when the link target is a directory,
        # which satisfies neither the plain-dir nor the pointer-file branch.
        # Realpath-resolve and inspect the target like a nested symlinked
        # .git: the redirect fires, and an armed target config/hooks fire.
        resolved = os.path.realpath(root_dotgit)
        findings.append(_gitdir_pointer_finding(
            ".git", resolved, "the checkout's own .git is a symlink "
            "redirecting git metadata, which git itself never creates"))
        if os.path.isdir(resolved):
            _scan_git_dir(resolved, ".git", findings, state)
        elif os.path.isfile(resolved):
            _scan_root_gitdir_file(resolved, repo_abs, findings, state)
    elif os.path.isdir(root_dotgit):
        config_path = os.path.join(root_dotgit, "config")
        if os.path.isfile(config_path):
            try:
                with open(config_path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    config_text = fh.read(1024 * 1024)
            except OSError:
                config_text = ""
            findings.extend(_config_findings(
                config_text, os.path.join(".git", "config"),
                rule_id=R_ROOT_CONFIG, severity="high", shipped=False))
    elif os.path.isfile(root_dotgit):
        _scan_root_gitdir_file(root_dotgit, repo_abs, findings, state)

    for root, dirs, files in os.walk(repo_abs, followlinks=False):
        if time.monotonic() > deadline:
            state["incomplete"] = True
            break
        rel_root = os.path.relpath(root, repo_abs)
        kept = []
        for d in dirs:
            if d.lower() == ".git":
                if rel_root == ".":
                    continue  # the checkout's own metadata, handled above
                git_fs = os.path.join(root, d)
                git_rel = os.path.normpath(os.path.join(rel_root, d))
                _shipped_git_at(git_fs, git_rel, findings, state)
                continue  # never descend into any .git directory
            if d in core.IGNORE_DIRS:
                # Ignored for ordinary content, swept for .git metadata only.
                _sweep_ignored_root(os.path.join(root, d),
                                    os.path.normpath(os.path.join(rel_root, d)),
                                    repo_abs, findings, deadline, state)
                continue
            kept.append(d)
        dirs[:] = kept
        for f in files:
            if f.lower() != ".git" or rel_root == ".":
                continue  # root-level pointer files handled above
            pointer_fs = os.path.join(root, f)
            _scan_nested_gitdir_file(
                pointer_fs, os.path.normpath(os.path.join(rel_root, f)),
                repo_abs, findings, state)

    if state["incomplete"]:
        findings.append(core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="Git config scan incomplete",
            description="Wall-clock budget exhausted; part of the tree was "
                        "not inspected for shipped .git content.",
            file=repo_path, line=0, snippet="", category="scan-incomplete",
        ))


# ---------------------------------------------------------------------------
# .gitmodules: update = !command
# ---------------------------------------------------------------------------

def scan_gitmodules_text(text, file_label):
    """Flag `update = !command` in .gitmodules content (arbitrary shell
    execution on `git submodule update`)."""
    findings = []
    for section, _sub, key, value, line_no, line_text in _parse_config(text):
        if section == "submodule" and key == "update" \
                and value.lstrip().startswith("!"):
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="critical", rule_id=R_GITMODULES_EXEC,
                title=".gitmodules submodule update executes a shell command",
                description=(
                    f"`update = {value}` in {file_label} runs an arbitrary "
                    f"shell command on `git submodule update`. Legitimate "
                    f"submodule updates name a strategy (checkout, merge, "
                    f"rebase), never a shell command."
                ),
                file=file_label, line=line_no, snippet=line_text[:120],
                category="git-config-exec", evidence_class="direct",
            ))
    return findings


# ---------------------------------------------------------------------------
# Staged-plant chain: write exec-capable git config AND rename/copy a dir to
# .git
# ---------------------------------------------------------------------------

# Arm 1: a write of an exec-capable git config key. Deliberately covers code
# (`git config`, `git -c`, config-set APIs, heredoc/redirect into .git/config,
# ini-style assignment) and prose directives; the conjunction with arm 2 is
# what keeps this precise.
_CONFIG_WRITE_RE = re.compile(r"""(?ix)
    \bgit\s+(?:(?-i:-C)\s+\S+\s+)*(?:(?-i:-c)\s+|config\s+(?:--[a-z-]+\s+)*)[^\n]{0,80}?
        (?:
            (?:core\.)?fsmonitor(?![\w-])(?!\s*[= ]\s*(?:true|false|yes|no|on|off|0|1)(?![\w/\\.]))
          | (?:core\.)?hookspath(?![\w-])(?!\s*[= ]\s*(?:/dev/null|nul)(?![\w/\\.]))
          | (?:core\.)?(?:sshcommand|pager|editor|askpass)(?![\w-])
          | gpg\.program(?![\w-])
          | diff\.external(?![\w-])
          | filter\.[\w-]+\.(?:clean|smudge|process)(?![\w-])
        )
    | \bgit\s+config\s+(?:--[a-z-]+\s+)*credential\.helper\b
    | \bGIT_CONFIG_KEY_\d+\s*=.*(?:fsmonitor|hookspath|sshcommand)
    | \b(?:core\.)?fsmonitor\s*=\s*(?!(?:true|false|yes|no|on|off|0|1)(?![\w/\\.]))\S
    | \b(?:core\.)?hookspath\s*=\s*(?!(?:/dev/null|nul)(?![\w/\\.]))\S
    | \b(?:core\.)?(?:sshcommand|askpass)\s*=\s*\S
    | \b(?:gpg\.program|diff\.external|filter\.[\w-]+\.(?:clean|smudge|process))
        \s*=\s*\S
    | \bcredential\.helper\s*=\s*(?:!|[^\s"']*[\\/])
    | (?:>>?|open\s*\(\s*|write(?:text)?\s*\(\s*)[^\n]{0,40}?\.git[/\\]config\b
""")
# Notes on the shape:
#   - `-c` (config override) and `-C` (chdir) are matched CASE-SENSITIVELY
#     inside an otherwise case-insensitive regex: under re.I the two collide,
#     and `git -C repo fsmonitor--daemon status` (running the daemon
#     subcommand) looked exactly like a config write. `git -C <path> config
#     <key> <value>` is still recognised.
#   - Key names require a non-word/non-dash boundary so `fsmonitor--daemon`
#     does not match the fsmonitor key.
#   - fsmonitor/hookspath matches carrying INERT values (true/false,
#     /dev/null) are excluded here just like in the config parser: setting
#     the built-in fsmonitor or disabling hooks is protective, not a write
#     an attacker would stage.

# Cheap per-line superset of arm 1: if none of these tokens is present (and
# the line carries no `.git`), neither arm can match, so the line is skipped
# without running the heavy patterns. This keeps whole-tree scans of very
# large repos (git/git) inside the wall-clock budget.
_ARM1_HINT_RE = re.compile(r"""(?ix)
    fsmonitor | hookspath | sshcommand | credential\.helper
    | gpg\.program | diff\.external | askpass | GIT_CONFIG_KEY
    | filter\.[\w-]+\.(?:clean|smudge|process)
    | pager | editor
    | \bgit\s+(?:-c|-C|config)\b
""")

# Arm 2 is NOT a single regex. A plant line is recognised structurally:
#   - shell/cmd/PowerShell rename & copy verbs (mv, ren, rename, move,
#     Move-Item, Rename-Item, cp, copy, Copy-Item, xcopy, robocopy) whose
#     TARGET argument is exactly `.git` (basename) or a variable holding it;
#   - Python/Node rename/move/copy calls (os.rename/os.replace, shutil.move/
#     copy/copytree, fs.rename/renameSync/move/moveSync/copy/copySync,
#     pathlib .rename) whose target argument is the literal '.git' or a
#     variable holding it.
# Exact-basename matching kills the round-1 false positives (`mv proj.git
# .../proj.git`, `mv "$1" "$1.git"`), and one-hop variable resolution catches
# the round-1 evasions (`target=.git; mv stage "$target"`, quoted variants,
# trailing flags like `Move-Item staging .git -Force`).

_MOVE_VERBS = frozenset(
    {"mv", "ren", "rename", "move", "move-item", "rename-item"})
_COPY_VERBS = frozenset(
    {"cp", "copy", "copy-item", "xcopy", "robocopy"})
_PS_TARGET_PARAMS = frozenset({"-destination", "-dest", "-target"})
_PS_SOURCE_PARAMS = frozenset({"-path", "-literalpath", "-source"})
# Flags known to consume a separate value operand; the value must not be
# mistaken for a positional (Move-Item staging .git -Filter *.tmp). Flags
# outside this set that take values are a documented limit.
_FLAGS_TAKING_VALUES = frozenset(
    {"-filter", "-include", "-exclude", "-credential"})

# Quote-aware shell tokeniser. Adjacent quoted and unquoted fragments stay
# one token, so shell quote-concatenation ("."git) survives tokenisation.
_TOKEN_RE = re.compile(r"""(?:"[^"\n]*"|'[^'\n]*'|[^\s'"])+""")

# Cheap per-line superset of the arm-2 call idioms, gated behind a literal
# substring prefilter at the use site: an inline call operand that
# obfuscates the `.git` spelling (os.rename(stage, '.'+'git'),
# fs.renameSync(a, `.gi${'t'}`)) carries no `.git` substring and matches no
# arm-1 hint, so without this it would slip the per-line gate. Shell
# obfuscations need no hint (the gate strips their quoting/escaping) and
# same-line assignments open the gate via line_assigns_git. Folding these
# alternatives into _ARM1_HINT_RE instead measurably slowed whole-tree
# scans (git/git over budget); a rare second regex behind four memchr-fast
# substring checks keeps the round-3 cost.
_ARM2_CALL_RE = re.compile(r"""(?ix)
    \b(?:os\.(?:rename|replace)
      | shutil\.(?:move|copy|copy2|copytree)
      | fs\.(?:rename|renameSync|move|moveSync|copy|copySync)
      | \.rename)\s*\(
""")


def _split_segments(line):
    """Split a line into (offset, segment) command segments on ;, |, & -
    quote-aware, so a separator inside a quoted string ("a;b") does not
    invent command boundaries the shell never parses."""
    segments = []
    start = 0
    quote = None
    for i, ch in enumerate(line):
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in ";|&":
            segments.append((start, line[start:i]))
            start = i + 1
    segments.append((start, line[start:]))
    return segments


# Python/Node/plant call idioms; the target is the LAST argument
# (os.rename(src, dst), shutil.move(src, dst), fs.renameSync(a, b),
# Path(x).rename(dst), shutil.copytree(src, dst), fs.copySync(a, b)). One
# level of nested parens is allowed inside the argument list so calls such
# as os.rename(str(stage), '.git') still match; deeper nesting is a
# documented limit.
_CALL_TARGET_RE = re.compile(r"""(?ix)
    (?: os\.(?:rename|replace)
      | shutil\.(?:move|copy|copy2|copytree)
      | fs\.(?:rename|renameSync|move|moveSync|copy|copySync)
      | \.rename )\s*\((?P<args>(?:[^()\n]|\([^()\n]*\))*)\)""")

# Trailing callback argument of the fs.rename(a, '.git', cb) family: arrow
# functions and `function` expressions are recognised and dropped before the
# target argument is picked. A bare-identifier callback stays a documented
# limit.
_CALLBACK_ARG_RE = re.compile(
    r"^\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")


def _split_call_args(args):
    """Split a call argument list on top-level commas; commas inside nested
    parens/brackets/braces belong to their argument."""
    out = []
    depth = 0
    current = []
    for ch in args:
        if ch == "," and depth == 0:
            out.append("".join(current))
            current = []
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        current.append(ch)
    out.append("".join(current))
    return out

# Assignment of any RHS in every supported syntax: shell (bare/local/export/
# typeset/declare), cmd (set, optionally fully quoted), PowerShell ($name),
# Python and Node (const/let/var). Tracked for FLOW-AWARE resolution: the
# last assignment before a use wins, and assignments after a use do not arm
# it - `target=.git` followed by `target=backup` leaves the move's runtime
# destination at backup.
_ASSIGN_ANY_RE = re.compile(r"""(?xm)
    (?:^|(?<=[;&|]))[ \t]*
    (?:(?:const|let|var|local|export|typeset|declare|set)[ \t]+)?
    [\x27"]?\$?(?P<name>[A-Za-z_][A-Za-z0-9_]*)[\x27"]?
    [ \t]*=[ \t]*
    (?P<value>\$\([^()\n]*\)
      | (?:['"][^'"\n]*['"][ \t]*\+[ \t]*)+['"][^'"\n]*['"]
      | (?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s;|&"'`])+)""")

_VAR_REF_RE = re.compile(r"""(?x)
    \$\{([A-Za-z_]\w*)\} | \$([A-Za-z_]\w*)
    | %([A-Za-z_]\w*)% | !([A-Za-z_]\w*)!""")

_CMD_SUB_RE = re.compile(r"^\$\(([^()\n]*)\)$", re.DOTALL)
_TPL_CONST_RE = re.compile(r"\$\{\s*(['\"])(.*?)\1\s*\}")
_CONCAT_PIECE_RE = re.compile(r"""\s*(['"])([^'"]*?)\1\s*""")


def _python_concat(text):
    """Python/Node constant string concatenation ('.'+'git', "." + "git")
    resolved to the joined string, or None when the expression is not
    purely quoted constants joined by +."""
    if "+" not in text:
        return None
    bodies = []
    pos = 0
    while pos < len(text):
        m = _CONCAT_PIECE_RE.match(text, pos)
        if not m:
            return None
        bodies.append(m.group(2))
        pos = m.end()
        if pos < len(text):
            if text[pos] != "+":
                return None
            pos += 1
    return "".join(bodies)


def _expand_var_refs(text, state):
    """Expand $v/${v}/%v%/!v! refs from the flow state; None when any ref is
    unbound (an unprovable value never arms a target)."""
    out = []
    pos = 0
    for m in _VAR_REF_RE.finditer(text):
        out.append(text[pos:m.start()])
        name = next(g for g in m.groups() if g).lower()
        value = state.get(name)
        if not isinstance(value, str):
            return None
        out.append(value)
        pos = m.end()
    out.append(text[pos:])
    return "".join(out)


def _resolve_assigned_value(raw, state):
    """Resolve an assignment RHS to a concrete string, or None when it is
    not cheaply provable. Covered classes: multi-hop variables (b=$a, and
    bare Python/Node b=a), simple constant command substitution
    ($(printf .git), $(echo .git)), quote-concatenation ("."git), backslash
    escapes (.g\\it), environment-style concatenation (.$suffix with suffix
    bound), Python constant concatenation ('.'+'git'), and Node template
    literals (`.git`, `.gi${'t'}`). Anything deeper - functions, loops,
    non-constant substitutions - is a documented limit: it resolves to None
    and arms nothing."""
    t = raw.strip()
    if not t:
        return ""
    m = _CMD_SUB_RE.match(t)
    if m:
        inner = m.group(1).strip()
        parts = inner.split(None, 1)
        if len(parts) == 2 and parts[0] in ("printf", "echo"):
            return _resolve_assigned_value(parts[1], state)
        return None
    if len(t) >= 2 and t.startswith("`") and t.endswith("`"):
        t = t[1:-1]  # Node template literal / shell backtick substitution
    # Node template constant interpolation: ${'git'} / ${"git"}.
    t = _TPL_CONST_RE.sub(lambda m: m.group(2), t)
    concat = _python_concat(t)
    if concat is not None:
        t = concat
    elif len(t) >= 2 and t[0] in "'\"" and t[-1] == t[0]:
        t = t[1:-1]
    # Quote-concatenation across fragments ("."git) and backslash escapes
    # (.g\it): removing the quoting/escaping characters reproduces the
    # runtime string for these cheap forms.
    t = t.replace("'", "").replace('"', "").replace("\\", "")
    t = _expand_var_refs(t, state)
    if t is None:
        return None
    # Bare Python/Node two-hop: b=a resolves through the flow state when a
    # is bound; otherwise the word is a plain literal (shell semantics).
    if re.fullmatch(r"[A-Za-z_]\w*", t) and t.lower() in state:
        return state[t.lower()]
    return t


def _token_is_git_target(token, var_state, allow_bare_name):
    """True when a command/call TARGET token resolves to exactly `.git`
    (compared case-insensitively: on Windows and macOS a `.GIT` directory IS
    git's metadata directory): a literal path whose basename is .git (either
    quote style, quote-concatenated fragments like "."git, or
    backslash-escaped like .g\\it), or a variable reference ($v, ${v}, %v%,
    !v!, or a bare identifier in call syntax) whose last assignment BEFORE
    this use resolves to .git."""
    t = token.strip()
    if len(t) >= 2 and t[0] in "'\"" and t[-1] == t[0]:
        t = t[1:-1]
    if not t:
        return False
    m = _VAR_REF_RE.fullmatch(t)
    if m:
        name = next(g for g in m.groups() if g)
        value = var_state.get(name.lower())
        return isinstance(value, str) and value.lower() == ".git"
    candidates = {t, t.replace("'", "").replace('"', "")}
    candidates |= {c.replace("\\", "") for c in list(candidates)}
    for cand in candidates:
        base = cand.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if base.lower() == ".git":
            return True
    if allow_bare_name and re.fullmatch(r"[A-Za-z_]\w*", t):
        value = var_state.get(t.lower())
        return isinstance(value, str) and value.lower() == ".git"
    # Cheap INLINE literal operands resolve through the same classes as
    # assignment RHSs: mv stage "$(printf .git)" and
    # os.rename(stage, '.'+'git') arm exactly like their
    # assignment-mediated spellings. Anything unprovable resolves to None
    # and arms nothing.
    for spelling in (token.strip(), t):
        resolved = _resolve_assigned_value(spelling, var_state)
        if isinstance(resolved, str):
            base = resolved.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            if base.lower() == ".git":
                return True
    return False


def _shell_segment_plants_git(segment, var_state):
    """One shell/cmd/PowerShell command segment: a rename/copy verb as the
    command word, whose target operand resolves to `.git`."""
    tokens = _TOKEN_RE.findall(segment.strip())
    if not tokens:
        return False
    verb_i = 0
    if tokens[0].lower() in ("sudo", "command", "env") and len(tokens) > 1:
        verb_i = 1
    verb = tokens[verb_i].lower()
    if verb not in _MOVE_VERBS | _COPY_VERBS:
        return False
    args = tokens[verb_i + 1:]
    positionals = []
    named_target = None
    i = 0
    windows_verb = verb in ("xcopy", "robocopy")
    while i < len(args):
        tok = args[i]
        low = tok.lower()
        if low in _PS_SOURCE_PARAMS and i + 1 < len(args):
            i += 2  # explicit source operand: not the target
            continue
        if low in _PS_TARGET_PARAMS and i + 1 < len(args):
            named_target = args[i + 1]
            i += 2
            continue
        if low in ("-t", "--target-directory") and i + 1 < len(args):
            named_target = args[i + 1]
            i += 2  # GNU mv/cp: -t/--target-directory names the target
            continue
        if low.startswith("--target-directory="):
            named_target = tok.split("=", 1)[1]
            i += 1
            continue
        if low in _FLAGS_TAKING_VALUES and i + 1 < len(args):
            i += 2  # a flag consuming a value: the value is not the target
            continue
        if low.startswith(tuple(p + ":" for p in _PS_TARGET_PARAMS)):
            named_target = tok.split(":", 1)[1]
            i += 1
            continue
        if low.startswith(tuple(p + ":" for p in _PS_SOURCE_PARAMS)):
            i += 1
            continue
        if tok.startswith("-"):
            i += 1  # a flag (mv -f, Move-Item -Force, ...): never the target
            continue
        if windows_verb and tok.startswith("/"):
            i += 1  # xcopy/robocopy /E /MIR-style option
            continue
        positionals.append(tok)
        i += 1
    if named_target is not None:
        return _token_is_git_target(named_target, var_state,
                                    allow_bare_name=False)
    if not positionals:
        return False
    if windows_verb:
        # robocopy/xcopy: source destination [files] [options] - the SECOND
        # positional is the destination, even when file masks follow it.
        if len(positionals) < 2:
            return False
        return _token_is_git_target(positionals[1], var_state,
                                    allow_bare_name=False)
    # mv/ren/move/cp/copy: the LAST positional is the destination, so
    # `mv .git backup` (disarming) and `mv proj.git .../proj.git` (ordinary
    # repo relocation) never satisfy the arm.
    return _token_is_git_target(positionals[-1], var_state,
                                allow_bare_name=False)


def _line_plants_git(line, state_at):
    """Arm 2: does this line rename or copy something to exactly `.git`?
    state_at(pos) yields the flow-aware variable bindings in effect at
    character offset pos (assignments later in the file - or later in this
    line - do not count)."""
    for m in _CALL_TARGET_RE.finditer(line):
        args = _split_call_args(m.group("args"))
        if len(args) >= 3 and _CALLBACK_ARG_RE.match(args[-1]):
            # fs.rename(a, '.git', cb): the callback is not the target.
            args = args[:-1]
        if args and _token_is_git_target(args[-1], state_at(m.start()),
                                         allow_bare_name=True):
            return True
    for offset, segment in _split_segments(line):
        if _shell_segment_plants_git(segment, state_at(offset)):
            return True
    return False


def scan_rename_chain_text(text, file_label):
    """Critical when ONE file both writes an exec-capable git config key and
    renames or copies a directory to `.git`. Either behaviour alone is common
    and legitimate; together they are the runtime plant for a nested-.git
    swap. The rename/copy arm resolves variables FLOW-SENSITIVELY (the last
    assignment before each use wins) and case-insensitively, covering the
    cheap indirection classes documented on _resolve_assigned_value -
    both in assignments and in cheap INLINE literal operands
    (mv stage "$(printf .git)", os.rename(stage, '.'+'git'))."""
    # File-level fast path (case-insensitive: `.GIT` is git's directory on
    # Windows/macOS), normalised for quoting/escaping so obfuscated
    # spellings ("."git, .g\it) cannot slip the gate.
    lowered = text.lower()
    if '.git' not in lowered:
        lowered = lowered.replace("'", "").replace('"', "").replace("\\", "")
    if '.git' not in lowered and not _ARM1_HINT_RE.search(text):
        return []
    var_state = {}        # name (lower) -> resolved value (str) or None
    has_git_var = False
    config_hit = None
    rename_hit = None
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw[: core.MAX_LINE_LENGTH]
        # Every assignment on this line, in textual order; a use resolves
        # against the assignments BEFORE it (and all prior lines).
        assigns = [(m.start(), m.group("name").lower(), m.group("value"))
                   for m in _ASSIGN_ANY_RE.finditer(line)]

        def state_at(pos, _assigns=assigns, _base=var_state):
            if not _assigns:
                return _base
            effective = dict(_base)
            for a_pos, a_name, a_raw in _assigns:
                if a_pos < pos:
                    effective[a_name] = _resolve_assigned_value(
                        a_raw, effective)
            return effective

        gate = line.lower()
        has_git = '.git' in gate or '.git' in gate.replace(
            "'", "").replace('"', "").replace("\\", "")
        # A line whose OWN assignment binds .git (const t = `.gi${'t'}`;
        # fs.renameSync(a, t); on one line) must not slip the gate: resolve
        # this line's assignments against the pre-line state.
        line_assigns_git = False
        if assigns and not (has_git or has_git_var):
            probe = state_at(len(line) + 1)
            line_assigns_git = any(
                isinstance(v, str) and v.lower() == ".git"
                for v in probe.values())
        if has_git or has_git_var or line_assigns_git:
            arm2_hint = False  # gate already open
            hint = True
        else:
            hint = _ARM1_HINT_RE.search(line)
            if hint:
                arm2_hint = False
            else:
                # memchr-fast prefilter before the second regex.
                arm2_hint = (
                    "rename" in gate or "move" in gate
                    or "copy" in gate or "replace" in gate) \
                    and _ARM2_CALL_RE.search(line) is not None
                hint = arm2_hint
            if not hint:
                # No arm can match on this line, but its assignments still
                # update the flow state (e.g. suffix=git feeding a later
                # target=.$suffix).
                for _pos, a_name, a_raw in assigns:
                    var_state[a_name] = _resolve_assigned_value(
                        a_raw, var_state)
                if assigns:
                    has_git_var = any(
                        isinstance(v, str) and v.lower() == ".git"
                        for v in var_state.values())
                continue
        if config_hit is None and _CONFIG_WRITE_RE.search(line):
            config_hit = (line_no, raw.strip())
        if rename_hit is None and (has_git or has_git_var
                                   or line_assigns_git or arm2_hint) \
                and _line_plants_git(line, state_at):
            rename_hit = (line_no, raw.strip())
        if config_hit and rename_hit:
            break
        for _pos, a_name, a_raw in assigns:
            var_state[a_name] = _resolve_assigned_value(a_raw, var_state)
        if assigns:
            has_git_var = any(
                isinstance(v, str) and v.lower() == ".git"
                for v in var_state.values())
    if not (config_hit and rename_hit):
        return []
    return [core.Finding(
        scanner=SCANNER_NAME, severity="critical", rule_id=R_RENAME_CHAIN,
        title="Staged .git plant: writes executable git config and moves a directory to .git",
        description=(
            f"{file_label} writes an exec-capable git config key "
            f"(line {config_hit[0]}) and renames/copies a directory to "
            f"`.git` (line {rename_hit[0]}). Staging config under an "
            f"innocent name and moving it into place arms a previously clean "
            f"checkout: the next git operation in that workspace executes the "
            f"planted command."
        ),
        file=file_label, line=rename_hit[0],
        snippet=rename_hit[1][:120], category="git-config-exec",
        evidence_class="direct",
    )]


def _walk_content_rules(repo_path, ignore_patterns, findings, deadline):
    """walk_repo pass for .gitmodules and the staged-plant chain."""
    for file_path, rel_path in core.walk_repo(
            repo_path, ignore_patterns=ignore_patterns):
        if time.monotonic() > deadline:
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="low",
                title="Git config scan incomplete",
                description="Wall-clock budget exhausted; part of the tree was "
                            "not inspected for .gitmodules / plant-chain content.",
                file=repo_path, line=0, snippet="", category="scan-incomplete",
            ))
            break
        base = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as fh:
                raw = fh.read(_CHAIN_READ_BYTES)
        except OSError:
            continue
        text = raw.decode("utf-8", errors="replace")
        if base.lower() == ".gitmodules":
            findings.extend(scan_gitmodules_text(text, rel_path))
        findings.extend(scan_rename_chain_text(text, rel_path))


# ---------------------------------------------------------------------------
# Archive integration helpers (called by scan_archive)
# ---------------------------------------------------------------------------

def classify_git_member_path(member_name, is_dir=False):
    """Classify an archive member path for shipped-.git content.

    Returns (kind, git_root) where kind is one of "dir", "config", "hooks",
    "other", "gitdir_file", or None when the member carries no git metadata.
    Path separators are normalised so both zip and tar naming are covered.

    is_dir tells the classifier the archive itself marked the member as a
    directory (zip DOS directory bit / trailing slash, tar dir member): a
    bare `.git` DIRECTORY entry without a trailing slash is shipped metadata
    (critical), while a `.git` FILE entry is a gitdir pointer (high). Members
    under hooks/ count as hooks only for recognised git hook names; samples
    (any case) and arbitrary files are "other" - the .git root itself is
    still surfaced on presence.
    """
    norm = member_name.replace("\\", "/")
    is_dir_entry = is_dir or norm.endswith("/")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    lowered = [p.lower() for p in parts]
    if not parts:
        return None
    if lowered[-1] == ".git":
        git_root = "/".join(parts)
        if is_dir_entry:
            return ("dir", git_root)
        # `.git` as the final component of a FILE entry: a gitdir pointer.
        return ("gitdir_file", git_root)
    if ".git" in lowered:
        i = lowered.index(".git")
        git_root = "/".join(parts[:i + 1])
        rest = [p for p in parts[i + 1:]]
        if not rest:
            return ("dir", git_root)
        if rest[0].lower() == "hooks" and len(rest) >= 2:
            if _hook_name_or_none(rest[-1]) is not None:
                return ("hooks", git_root)
            return ("other", git_root)
        if [p.lower() for p in rest] == ["config"]:
            return ("config", git_root)
        return ("other", git_root)
    return None


def archive_shipped_git_finding(label, git_root):
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical", rule_id=R_ARCHIVE_GIT,
        title="Archive ships a .git directory",
        description=(
            f"{label} contains git metadata under {git_root}. Distribution "
            f"archives never legitimately carry a .git directory; its config "
            f"and hooks execute commands when anyone (human or agent CLI) "
            f"runs git inside the extracted workspace."
        ),
        file=label, line=0, snippet=git_root + "/",
        category="shipped-git-dir", evidence_class="direct",
    )


def archive_shipped_hooks_finding(label, member_name):
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical", rule_id=R_SHIPPED_HOOKS,
        title="Executable hook shipped inside archived .git/hooks",
        description=(
            f"{label} ships git hook {member_name}. Git executes hooks on "
            f"ordinary operations (commit, checkout, push) with the victim's "
            f"authority."
        ),
        file=label, line=0, snippet=member_name[:120],
        category="git-config-exec", evidence_class="direct",
    )


def archive_gitdir_finding(label, member_name):
    return core.Finding(
        scanner=SCANNER_NAME, severity="high", rule_id=R_GITDIR_PTR,
        title="Archive ships a gitdir pointer file",
        description=(
            f"{label} ships {member_name}, a `.git` pointer file redirecting "
            f"the git directory. Extracted into a workspace, it activates git "
            f"metadata the victim never inspected."
        ),
        file=label, line=0, snippet=member_name[:120],
        category="shipped-git-dir", evidence_class="direct",
    )


def scan_archive_member_content(data, member_name, vpath):
    """Content checks for archive members: armed .git/config, .gitmodules
    update-exec, and the staged-plant chain. Findings carry vpath."""
    findings = []
    text = data[:_CHAIN_READ_BYTES].decode("utf-8", errors="replace")
    cls = classify_git_member_path(member_name)
    if cls and cls[0] == "config":
        findings.extend(_config_findings(
            text, vpath, rule_id=R_ARMED_CONFIG, severity="critical",
            shipped=True, line_numbers=False))
    if os.path.basename(member_name).lower() == ".gitmodules":
        findings.extend(scan_gitmodules_text(text, vpath))
    findings.extend(scan_rename_chain_text(text, vpath))
    return findings


def scan_file(file_path, rel_path):
    """Per-file content checks (used by the benign-corpus gate and any host
    that scans file-at-a-time): .gitmodules update-exec and the staged-plant
    chain. Shipped-.git detection is repo-level and lives in scan_repo."""
    try:
        with open(file_path, "rb") as fh:
            raw = fh.read(_CHAIN_READ_BYTES)
    except OSError:
        return []
    text = raw.decode("utf-8", errors="replace")
    findings = []
    if os.path.basename(file_path).lower() == ".gitmodules":
        findings.extend(scan_gitmodules_text(text, rel_path))
    findings.extend(scan_rename_chain_text(text, rel_path))
    return findings


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def scan_repo(repo_path, ignore_patterns=None):
    findings = []
    deadline = time.monotonic() + TOTAL_BUDGET_SEC
    if ignore_patterns is None:
        ignore_patterns = core.load_ignore_patterns(repo_path)
    _walk_shipped_git(repo_path, findings, deadline)
    _walk_content_rules(repo_path, ignore_patterns, findings, deadline)
    return findings


def main():
    args = core.parse_common_args(sys.argv, "Executable Git Configuration Scanner")
    repo_path = args.repo_path
    core.emit_status(args.format, f"[*] Scanning for executable git configuration in {repo_path}...")
    findings = scan_repo(repo_path)
    core.emit_status(args.format, f"[+] Git configuration scan complete: {len(findings)} finding(s).")
    core.output_findings(findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
