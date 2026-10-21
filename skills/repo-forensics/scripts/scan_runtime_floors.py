#!/usr/bin/env python3
"""
scan_runtime_floors.py - Vulnerable language-runtime declaration scanner

Engine-level vulnerabilities are not malicious code and no package IOC catches
them: PHP2Shell (CVE-2026-109618 / CVE-2026-109619, disclosed 2026-10-21) is a
use-after-free in the PHP engine itself, exploitable on a clean "Hello World"
deploy. What a repository CAN tell you is which runtime it declares. This
scanner reads those declarations and flags the ones pinned to - or capped
below - a patched floor:

  - composer.json        require / require-dev "php" constraints and
                         config.platform.php exact pins
  - composer.lock        platform / platform-overrides "php" entries
  - Dockerfile*          FROM php:<tag>, including ARG-resolved versions
  - docker-compose*.yml  image: php:<tag> and <image>:...phpX.Y tags
  - .github/workflows/*  setup-php php-version pins and matrix php lists
                         (advisory severity - CI testing an old branch is
                         legitimate for libraries)

The floors are DATA (data/runtime_floors.json), keyed by advisory, so the
next engine-level event (any runtime) is a data edit, not a code change.

Flagging posture (false-positive discipline):
  - EXACT pins below a floor or on an end-of-life branch: flag.
  - Constraints that CANNOT resolve to any patched version: flag.
  - Constraints that admit a patched version (e.g. ^8.2, >=7.4): silent. A
    range is not a deployment; the concrete pins above carry the signal.
  - Moving minor tags on maintained branches (php:8.2): low note to rebuild,
    because a cached pull from before the patch is still vulnerable.
  - Unparseable constraints: silent. This scanner only flags what it is
    sure about.

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core  # noqa: E402

SCANNER_NAME = "runtime_floors"

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '..', 'data', 'runtime_floors.json')

MAX_READ_BYTES = core.MAX_FILE_SIZE_MB * 1024 * 1024


def load_runtime_floors(path=DATA_PATH):
    """Load the advisory database. Returns (runtimes_dict, error_str)."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        return {}, str(e)
    if not isinstance(data, dict):
        return {}, "top level is not an object"
    major = str(data.get('schema_version', '')).split('.')[0]
    if major != '1':
        return {}, "unsupported schema_version %r" % (data.get('schema_version'),)
    runtimes = data.get('runtimes')
    if not isinstance(runtimes, dict):
        return {}, "missing 'runtimes' object"
    for name, raw in runtimes.items():
        if not isinstance(raw, dict):
            return {}, "runtime %r is not an object" % (name,)
        advs = raw.get('advisories')
        if not isinstance(advs, list) or not all(isinstance(a, dict) for a in advs):
            return {}, "runtime %r has a malformed 'advisories' list" % (name,)
    return runtimes, None


def parse_version(text):
    """Parse a version prefix like '8.1', 'v8.1.4', '8.1.4RC2' -> (8, 1, 4).
    Missing segments pad with 0. None when there is no numeric prefix."""
    if not isinstance(text, str):
        return None
    m = re.match(r'^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?', text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def _branch_key(v):
    return (v[0], v[1])


def _next_branch(branch):
    return (branch[0], branch[1] + 1, 0)


class Advisory:
    """One runtime advisory: patched floors per maintained branch + EOL line."""

    def __init__(self, runtime, raw):
        self.runtime = runtime
        self.id = raw.get('id', 'unknown')
        self.title = raw.get('title', '')
        self.cves = list(raw.get('cves', []))
        self.disclosed = raw.get('disclosed', '')
        self.references = list(raw.get('references', []))
        self.eol_note = raw.get('eol_note', '')
        self.floors = {}
        for branch, floor in (raw.get('patched_floors') or {}).items():
            b = parse_version(branch)
            f = parse_version(floor)
            if b and f:
                self.floors[_branch_key(b)] = (f, floor)
        eb = parse_version(raw.get('eol_below', ''))
        self.eol_below = _branch_key(eb) if eb else None

    @property
    def cve_label(self):
        return ' / '.join(self.cves) if self.cves else self.id

    @property
    def reference(self):
        return self.references[0] if self.references else ''

    def check_pin(self, version_text):
        """Check one concrete version. Returns (severity, kind, detail) or None."""
        v = parse_version(version_text)
        if v is None:
            return None
        branch = _branch_key(v)
        if self.eol_below and branch < self.eol_below:
            return ('critical', 'eol',
                    "%s %d.%d is end-of-life and receives NO patch for %s. %s"
                    % (self.runtime, v[0], v[1], self.cve_label, self.eol_note))
        if branch in self.floors:
            floor, floor_text = self.floors[branch]
            if v < floor:
                return ('high', 'below-floor',
                        "%s %d.%d.%d is below the %s patched floor %s"
                        % (self.runtime, v[0], v[1], v[2], self.cve_label, floor_text))
        return None


# --- Composer constraint evaluation -----------------------------------------
#
# The only question asked of a constraint is "can it resolve to a patched
# release?". Each ||-alternative reduces to a coarse [lower, upper) interval.
# Intervals are deliberately approximate, and every ambiguity resolves toward
# SILENT, because a range that admits a patched release is not a vulnerable
# deployment.

_OPS = ['>=', '<=', '>', '<', '=']
_OP_RE = re.compile('^(' + '|'.join(_OPS) + r')\s*(\S+)$')


def _bump(version_tuple, segment):
    """Increment one segment of a version tuple, zeroing what follows.
    (8,1,4) seg1 -> (8,2,0)."""
    parts = list(version_tuple) + [0, 0, 0]
    parts[segment] += 1
    for i in range(segment + 1, 3):
        parts[i] = 0
    return tuple(parts[:3])


def _interval_of_token(token):
    """One comparator token -> (lower, upper) tuple bounds, lower-inclusive /
    upper-exclusive (None = unbounded). None when unrecognizable."""
    token = token.strip().rstrip(',')
    if not token:
        return None
    # wildcard ranges: 8.1.* / 8.1.x / 8.* / *
    if '*' in token or re.search(r'(?:^|\.)x$', token, re.IGNORECASE):
        parts = re.split(r'[.*]', token.lower())
        parts = [p for p in parts if p not in ('', 'x')]
        if not parts or not all(p.isdigit() for p in parts):
            return (None, None)  # bare '*' - everything
        if len(parts) == 1:
            base = (int(parts[0]), 0, 0)
            return (base, _bump(base, 0))
        base = (int(parts[0]), int(parts[1]), 0)
        return (base, _bump(base, 1))
    m = _OP_RE.match(token)
    if m:
        op, ver = m.group(1), m.group(2)
        v = parse_version(ver)
        if v is None:
            return None
        if op == '>=':
            return (v, None)
        if op == '>':
            return (_bump(v, 2), None)
        if op == '<=':
            return (None, _bump(v, 2))
        if op == '<':
            return (None, v)
        return (v, _bump(v, 2))  # '='
    m = re.match(r'^(\^|~)\s*(\S+)$', token)
    if m:
        op, ver = m.group(1), m.group(2)
        v = parse_version(ver)
        if v is None:
            return None
        if op == '^':
            # >=v, < next major (0.x: < next minor; 0.0.x: exact-ish)
            if v[0] > 0:
                upper = _bump(v, 0)
            elif v[1] > 0:
                upper = _bump(v, 1)
            else:
                upper = _bump(v, 2)
            return (v, upper)
        # '~': ~8.1 -> <9.0 (next major when no patch given);
        #      ~8.1.2 -> <8.2 (next minor when patch given)
        if re.match(r'^\s*v?\d+\.\d+\.\d+', ver):
            upper = _bump(v, 1)
        else:
            upper = _bump(v, 0)
        return (v, upper)
    # bare version: exact pin (composer normalizes 8.1 -> 8.1.0)
    v = parse_version(token)
    if v is None:
        return None
    return (v, _bump(v, 2))


def _interval_of_alternative(alt):
    """AND-combine one ||-alternative's tokens into a single [lower, upper).
    Returns None when any token is unrecognizable (caller treats as unknown)."""
    alt = alt.strip()
    if not alt:
        return None
    # hyphen range: "8.0 - 8.3" (partial upper widens: 8.0 - 8.3 = <8.4)
    hm = re.match(r'^(\S+)\s+-\s+(\S+)$', alt)
    if hm:
        lo = parse_version(hm.group(1))
        hi_text = hm.group(2)
        hi = parse_version(hi_text)
        if lo is None or hi is None:
            return None
        if re.match(r'^\s*v?\d+\.\d+\.\d+', hi_text):
            upper = _bump(hi, 2)  # inclusive of the patch
        elif re.match(r'^\s*v?\d+\.\d+$', hi_text):
            upper = _bump(hi, 1)
        else:
            upper = _bump(hi, 0)
        return (lo, upper)
    lower, upper = None, None
    for token in re.split(r'[\s,]+', alt):
        if not token:
            continue
        iv = _interval_of_token(token)
        if iv is None:
            return None
        lo, hi = iv
        if lo is not None and (lower is None or lo > lower):
            lower = lo
        if hi is not None and (upper is None or hi < upper):
            upper = hi
    return (lower, upper)


def _intersects(interval, lo, hi):
    """Does [lower, upper) intersect [lo, hi)? None bounds are open."""
    lower, upper = interval
    if upper is not None and lo is not None and upper <= lo:
        return False
    if lower is not None and hi is not None and lower >= hi:
        return False
    return True


def check_constraint(constraint, advisory):
    """Check a composer `php` constraint against one advisory.

    Returns (severity, kind, detail) or None. SILENT unless NO alternative can
    resolve to a patched release:
      - no alternative reaches any maintained branch at all -> 'eol' critical
      - some alternative reaches a maintained branch but always below that
        branch's floor -> 'below-floor' high
    Anything else (admits a patched release, or unparseable) -> None.
    """
    if not isinstance(constraint, str) or not constraint.strip():
        return None
    alternatives = re.split(r'\|\|?', constraint)
    intervals = []
    for alt in alternatives:
        iv = _interval_of_alternative(alt)
        if iv is None:
            return None  # unknown syntax: say nothing rather than guess
        intervals.append(iv)

    reaches_maintained = False
    for iv in intervals:
        for branch in advisory.floors:
            if _intersects(iv, branch + (0,), _next_branch(branch)):
                reaches_maintained = True
                break
        if reaches_maintained:
            break

    if not reaches_maintained:
        if advisory.eol_below is not None:
            return ('critical', 'eol',
                    "constraint '%s' cannot resolve to any maintained %s branch; "
                    "every version it permits is end-of-life and unpatched for %s. %s"
                    % (constraint.strip(), advisory.runtime, advisory.cve_label,
                       advisory.eol_note))
        return None

    for iv in intervals:
        for branch, (floor, floor_text) in advisory.floors.items():
            if _intersects(iv, floor, _next_branch(branch)):
                return None  # some patched release satisfies the constraint
    return ('high', 'below-floor',
            "constraint '%s' permits maintained %s branches but always below the "
            "%s patched floor (%s)"
            % (constraint.strip(), advisory.runtime, advisory.cve_label,
               ', '.join(sorted(set(t for _, t in advisory.floors.values())))))


# --- Finding helpers ----------------------------------------------------------

def _read_text(filepath):
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(MAX_READ_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_READ_BYTES:
        raw = raw[:MAX_READ_BYTES]
    return raw.decode('utf-8-sig', errors='replace')  # utf-8-sig strips a BOM


def _finding(severity, title, description, rel_path, line, snippet, confidence=0.9):
    return core.Finding(
        scanner=SCANNER_NAME, severity=severity, title=title,
        description=description, file=rel_path, line=line,
        snippet=(snippet or '')[:120], category='vulnerable-runtime',
        confidence=confidence,
    )


def _pin_finding(advisory, version_text, source_desc, rel_path, line, snippet,
                 severity_override=None):
    hit = advisory.check_pin(version_text)
    if hit is None:
        return None
    severity, kind, detail = hit
    if severity_override:
        severity = severity_override
    return _finding(
        severity,
        "%s runtime pin vulnerable to %s: %s" % (advisory.runtime, advisory.cve_label,
                                                 version_text.strip()),
        "%s (%s). %s. Update to a patched release. Reference: %s"
        % (detail, source_desc, advisory.title, advisory.reference),
        rel_path, line, snippet)


def _constraint_finding(advisory, constraint, source_desc, rel_path, line, snippet,
                        severity_override=None):
    hit = check_constraint(constraint, advisory)
    if hit is None:
        return None
    severity, kind, detail = hit
    if severity_override:
        severity = severity_override
    return _finding(
        severity,
        "%s version constraint excludes every %s patch: %s"
        % (advisory.runtime, advisory.cve_label, constraint.strip()[:40]),
        "%s (%s). %s. Reference: %s"
        % (detail, source_desc, advisory.title, advisory.reference),
        rel_path, line, snippet)


# --- composer.json / composer.lock -------------------------------------------

def _find_php_line(content, section_hint):
    """Best-effort line number of the "php" key for attribution."""
    for i, line in enumerate(content.split('\n'), 1):
        if '"php"' in line:
            return i, line.strip()
    return 0, section_hint


def scan_composer_json(filepath, rel_path, advisories):
    findings = []
    content = _read_text(filepath)
    if content is None:
        return findings
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, RecursionError):
        return findings
    if not isinstance(data, dict):
        return findings
    line, snippet = _find_php_line(content, 'composer.json "php"')
    for section in ('require', 'require-dev'):
        reqs = data.get(section)
        if not isinstance(reqs, dict):
            continue
        constraint = reqs.get('php')
        if isinstance(constraint, str):
            for adv in advisories:
                f = _constraint_finding(adv, constraint,
                                        'composer.json %s.php' % section,
                                        rel_path, line, snippet)
                if f:
                    findings.append(f)
    platform = data.get('config', {}).get('platform') if isinstance(data.get('config'), dict) else None
    if isinstance(platform, dict):
        pin = platform.get('php')
        if isinstance(pin, str):
            for adv in advisories:
                f = _pin_finding(adv, pin, 'composer.json config.platform.php '
                                 '(the runtime Composer emulates for dependency '
                                 'resolution)', rel_path, line, snippet)
                if f:
                    findings.append(f)
    return findings


def scan_composer_lock(filepath, rel_path, advisories):
    findings = []
    content = _read_text(filepath)
    if content is None:
        return findings
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, RecursionError):
        return findings
    if not isinstance(data, dict):
        return findings
    line, snippet = _find_php_line(content, 'composer.lock platform php')
    for key in ('platform', 'platform-overrides'):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        value = section.get('php')
        if not isinstance(value, str):
            continue
        for adv in advisories:
            if key == 'platform-overrides':
                f = _pin_finding(adv, value, 'composer.lock platform-overrides.php '
                                 '(the runtime Composer emulates)', rel_path, line, snippet)
            else:
                f = _constraint_finding(adv, value, 'composer.lock platform.php',
                                        rel_path, line, snippet)
            if f:
                findings.append(f)
    return findings


# --- Dockerfile / docker-compose ----------------------------------------------

_TAG_VERSION_RE = re.compile(r'^v?(\d+(?:\.\d+){0,2})((?:[-+].*)?)$')
_ARG_RE = re.compile(r'^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S+))?\s*$')
_FROM_PHP_RE = re.compile(
    r'^\s*FROM\s+(?:--platform=\S+\s+)?["\']?(?:[\w.-]+(?::\d+)?/)*(?:library/)?php:([^\s"\']+)',
    re.IGNORECASE)
_VAR_RE = re.compile(r'^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}$|^\$([A-Za-z_][A-Za-z0-9_]*)$')
# <image>:...php8.1 or ...php8.1.4 tags (wordpress:php8.1-apache etc.)
_IMAGE_PHP_TAG_RE = re.compile(r'^\s*image:\s*["\']?[^\s"\']*:([^\s"\']*php(\d+(?:\.\d+){0,2})[^\s"\']*)["\']?', re.IGNORECASE)
_IMAGE_PHP_RE = re.compile(
    r'^\s*image:\s*["\']?(?:[\w.-]+(?::\d+)?/)*(?:library/)?php:([^\s"\']+)',
    re.IGNORECASE)


def _resolve_tag_var(tag, args):
    """Resolve a FROM tag that is a variable reference against collected ARG
    defaults. Returns the resolved literal, or None when unresolvable."""
    m = _VAR_RE.match(tag)
    if not m:
        return tag
    name = m.group(1) or m.group(3)
    default = m.group(2)
    if name in args and args[name]:
        return args[name]
    if default:
        return default
    return None


def _check_docker_tag(advisory, tag, source_desc, rel_path, line_no, line_text,
                      severity_override=None):
    """Check one image tag; returns a Finding or None. Handles exact pins,
    branch-only moving tags (EOL = critical; maintained = low rebuild note),
    and non-version tags (latest/cli/fpm -> silent)."""
    tag = tag.split('@', 1)[0]  # drop digest pins (image:tag@sha256:...)
    m = _TAG_VERSION_RE.match(tag)
    if not m:
        return None  # latest / cli / fpm-alpine etc: no version to judge
    version_text = m.group(1)
    v = parse_version(version_text)
    if v is None:
        return None
    segments = len(re.match(r'^v?(\d+(?:\.\d+){0,2})', version_text).group(1).split('.'))
    branch = _branch_key(v)
    if segments == 1:
        # php:8 is a moving MAJOR tag resolving to the newest 8.x, not 8.0.
        return None
    if advisory.eol_below and branch < advisory.eol_below:
        # Every release on an EOL branch is unpatched, moving tag or not.
        return _finding(
            'critical' if severity_override is None else severity_override,
            "%s image tag on end-of-life %s %d.%d: php:%s"
            % (advisory.runtime, advisory.runtime, v[0], v[1], tag),
            ("%s %d.%d is end-of-life and receives NO patch for %s. %s (%s). "
             "The only remediation is upgrading to a patched branch. Reference: %s")
            % (advisory.runtime, v[0], v[1], advisory.cve_label,
               advisory.eol_note, source_desc, advisory.reference),
            rel_path, line_no, line_text.strip())
    if branch in advisory.floors:
        floor, floor_text = advisory.floors[branch]
        if segments >= 3 and v < floor:
            # Exact patch pin below the floor.
            return _finding(
                'high' if severity_override is None else severity_override,
                "%s image tag vulnerable to %s: php:%s"
                % (advisory.runtime, advisory.cve_label, tag),
                ("%s %d.%d.%d is below the %s patched floor %s (%s). %s. "
                 "Rebuild on a patched tag. Reference: %s")
                % (advisory.runtime, v[0], v[1], v[2], advisory.cve_label,
                   floor_text, source_desc, advisory.title, advisory.reference),
                rel_path, line_no, line_text.strip())
        if segments == 2:
            # Moving MINOR tag on a maintained branch: resolves to the newest
            # patch on rebuild, but a cached pull from before it is vulnerable.
            return _finding(
                'low',
                "Moving %s image tag php:%s - rebuild to pull the %s patch"
                % (advisory.runtime, tag, advisory.cve_label),
                ("The moving tag php:%s resolves to the latest %d.%d.x, patched "
                 "at %s since %s, but an image pulled before then stays "
                 "vulnerable. Rebuild with --pull and verify the resolved "
                 "version. Reference: %s")
                % (tag, v[0], v[1], floor_text, advisory.disclosed,
                   advisory.reference),
                rel_path, line_no, line_text.strip(), confidence=0.6)
    return None


def scan_dockerfile(filepath, rel_path, advisories):
    findings = []
    content = _read_text(filepath)
    if content is None:
        return findings
    args = {}
    for line_no, line in enumerate(content.split('\n'), 1):
        am = _ARG_RE.match(line)
        if am and am.group(2):
            args[am.group(1)] = am.group(2)
            continue
        fm = _FROM_PHP_RE.match(line)
        if not fm:
            continue
        raw_tag = fm.group(1).strip()
        tag = _resolve_tag_var(raw_tag, args)
        if tag is None:
            continue  # ARG with no default: version unknowable here
        for adv in advisories:
            f = _check_docker_tag(adv, tag, 'Dockerfile FROM', rel_path, line_no, line)
            if f:
                findings.append(f)
    return findings


def scan_compose(filepath, rel_path, advisories):
    findings = []
    content = _read_text(filepath)
    if content is None:
        return findings
    for line_no, line in enumerate(content.split('\n'), 1):
        m = _IMAGE_PHP_RE.match(line)
        if m:
            # image is php:<tag>: the tag itself carries the version
            version_text = m.group(1)
        else:
            m = _IMAGE_PHP_TAG_RE.match(line)
            if not m:
                continue
            # <image>:...phpX.Y tag: extract the phpX.Y part
            pm = re.search(r'php(\d+(?:\.\d+){0,2})', m.group(1))
            if pm is None:
                continue
            version_text = pm.group(1)
        for adv in advisories:
            f = _check_docker_tag(adv, version_text, 'docker-compose image',
                                  rel_path, line_no, line)
            if f:
                findings.append(f)
    return findings


# --- GitHub workflows (setup-php) ---------------------------------------------
#
# Advisory severity only: a library CI matrix that tests old PHP branches is
# legitimate. Medium for EOL, low for below-floor, and the finding text says
# why it may not apply.

_PHP_VERSION_KEY_RE = re.compile(r'^\s*php-version:\s*["\']?([\d.]+)["\']?\s*$', re.IGNORECASE)
_MATRIX_PHP_KEY_RE = re.compile(r'^\s*php:\s*\[(.*?)\]\s*$', re.IGNORECASE)
_MATRIX_PHP_BLOCK_RE = re.compile(r'^(\s*)php:\s*$', re.IGNORECASE)
_MATRIX_ITEM_RE = re.compile(r'^\s*-\s*["\']?([\d.]+)["\']?\s*$')


def scan_workflow(filepath, rel_path, advisories):
    findings = []
    content = _read_text(filepath)
    if content is None:
        return findings
    versions = []  # (line_no, version_text, line)
    in_php_block = False
    php_block_indent = 0
    for line_no, line in enumerate(content.split('\n'), 1):
        if in_php_block:
            indent = len(line) - len(line.lstrip())
            im = _MATRIX_ITEM_RE.match(line)
            if line.strip() and indent > php_block_indent and im:
                versions.append((line_no, im.group(1), line))
                continue
            in_php_block = False
        m = _PHP_VERSION_KEY_RE.match(line)
        if m:
            versions.append((line_no, m.group(1), line))
            continue
        m = _MATRIX_PHP_KEY_RE.match(line)
        if m:
            for tok in re.split(r'[,]', m.group(1)):
                tok = tok.strip().strip('\'"')
                if re.match(r'^\d+(\.\d+){0,2}$', tok):
                    versions.append((line_no, tok, line))
            continue
        m = _MATRIX_PHP_BLOCK_RE.match(line)
        if m:
            in_php_block = True
            php_block_indent = len(m.group(1))
    for line_no, version_text, line in versions:
        # A minor-only CI pin (php-version: '8.3') is a MOVING tag: setup-php
        # resolves it to the newest 8.3.x on every run, so it picks up the
        # patch by itself. Only EOL pins and exact patch pins below the floor
        # carry signal in CI.
        for adv in advisories:
            hit = adv.check_pin(version_text)
            if hit is None:
                continue
            severity, kind, detail = hit
            if kind == 'below-floor':
                vm = re.match(r'^v?(\d+\.\d+)(?:\.(\d+))?', version_text)
                if vm is not None and vm.group(2) is None:
                    continue  # moving minor pin on a maintained branch
            severity = 'medium' if kind == 'eol' else 'low'
            findings.append(_finding(
                severity,
                "CI workflow pins %s %s, vulnerable to %s"
                % (adv.runtime, version_text, adv.cve_label),
                ("%s (GitHub Actions setup-php). Testing against an old branch "
                 "in CI is legitimate for libraries; flag only if this workflow "
                 "deploys or publishes from that runtime. %s. Reference: %s")
                % (detail, adv.title, adv.reference),
                rel_path, line_no, line.strip(), confidence=0.5))
    return findings


# --- Driver --------------------------------------------------------------------

_DOCKERFILE_RE = re.compile(r'^(Dockerfile(\..+|-.+)?|.+\.Dockerfile)$', re.IGNORECASE)
_COMPOSE_RE = re.compile(r'^(docker-)?compose(-.+)?\.ya?ml$', re.IGNORECASE)


def _target_kind(rel_path):
    base = os.path.basename(rel_path)
    if base == 'composer.json':
        return 'composer.json'
    if base == 'composer.lock':
        return 'composer.lock'
    if _DOCKERFILE_RE.match(base):
        return 'dockerfile'
    if _COMPOSE_RE.match(base):
        return 'compose'
    norm = rel_path.replace(os.sep, '/')
    if norm.startswith('.github/workflows/') and base.endswith(('.yml', '.yaml')):
        return 'workflow'
    return None


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Flag declared language runtimes pinned below a patched "
                    "vulnerability floor (data: runtime_floors.json)")
    parser.add_argument('path', help='Repository path to scan')
    parser.add_argument('--format', default='text', choices=['text', 'json'])
    args = parser.parse_args()

    repo_path = os.path.abspath(args.path)
    if not os.path.isdir(repo_path):
        print("[!] Path is not a directory: %s" % repo_path, file=sys.stderr)
        sys.exit(2)

    runtimes, err = load_runtime_floors()
    findings = []
    if err:
        # A gate that cannot run denies: no silent clean when the floor data
        # is missing or corrupt.
        findings.append(_finding(
            'medium',
            "Runtime-floor data unavailable",
            "data/runtime_floors.json could not be loaded (%s); vulnerable-"
            "runtime declarations were NOT checked. Restore the data file."
            % err,
            '', 0, '', confidence=0.0))
    else:
        advisories = []
        for runtime, raw in runtimes.items():
            for adv in (raw or {}).get('advisories', []):
                advisories.append(Advisory(raw.get('name', runtime), adv))

        ignore_patterns = core.load_ignore_patterns(repo_path)
        for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns,
                                                  skip_binary=True,
                                                  skip_lockfiles=False):
            kind = _target_kind(rel_path)
            if kind == 'composer.json':
                findings.extend(scan_composer_json(file_path, rel_path, advisories))
            elif kind == 'composer.lock':
                findings.extend(scan_composer_lock(file_path, rel_path, advisories))
            elif kind == 'dockerfile':
                findings.extend(scan_dockerfile(file_path, rel_path, advisories))
            elif kind == 'compose':
                findings.extend(scan_compose(file_path, rel_path, advisories))
            elif kind == 'workflow':
                findings.extend(scan_workflow(file_path, rel_path, advisories))

    core.output_findings(findings, args.format, SCANNER_NAME)


if __name__ == '__main__':
    main()
