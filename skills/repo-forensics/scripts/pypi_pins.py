#!/usr/bin/env python3
"""PyPI requirement parsing for the compromised-version checks.

pip/uv install commands, requirements files and pyproject strings all spell a
pin differently (`litellm==1.107.0`, `"LiteLLM[proxy] == 1.107.0.0"`,
`litellm @ https://.../litellm-1.107.0-py3-none-any.whl`). This module turns
each spelling into (normalised name, version) so one lookup against the PyPI
compromised-version map covers every caller.

Stdlib-only leaf module: pre_scan.py imports it on the hot path of every shell
command, so it must stay cheap and must never raise on hostile input.

Matching is deliberately limited to what is knowable offline:
  * exact pins (`==X`, `===X`) match when X is the same PEP 440 version;
  * a trailing wildcard (`==1.107.*`) matches when the compromised version is
    inside the prefix;
  * ranges (`>=`, `~=`, `<`) and bare names do NOT match. They resolve through
    the index at install time, and compromised releases are usually yanked, so
    blocking every range that merely includes one would block good installs for
    ever. The wheel/archive scanners are the control for those.
"""

import re

_NAME_RE = re.compile(r'^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$', re.S)
_SHELL_OPS = {'&&', '||', ';', '|', '&', ';;', '|&', '>', '>>', '<', '<<', '2>', '2>>'}
_OPERATOR_CHARS = '=<>!~'
_WORD_RE = re.compile(r'(?:"[^"]*"|\'[^\']*\'|[^\s"\'&|;<>()])+|[&|;<>()]+')
# Matched with .match() and no `$`, then the remainder is checked by hand:
# a tail class overlapping the digit groups made the single-regex form
# quadratic on long digit/dot strings.
_VERSION_RE = re.compile(r'(?:\d+!)?v?(\d+(?:\.\d+)*)', re.I)


def normalize_name(name):
    """PEP 503 name normalisation: case-fold, runs of -_. collapse to '-'."""
    if not isinstance(name, str):
        return ''
    return re.sub(r'[-_.]+', '-', name.strip()).lower()


def _release(version):
    """Release tuple of a PLAIN version (no pre/post/dev/local), trailing
    zeros stripped so 1.107 == 1.107.0 == 1.107.0.0. None for anything else
    (including 1.107.0.post1, 1.107.0rc1, 1.107.0+local)."""
    if not isinstance(version, str):
        return None
    m = _VERSION_RE.match(version.strip())
    if not m or m.end() != len(version.strip()):
        return None
    parts = [int(p) for p in m.group(1).split('.')]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def spec_hits(spec, bad_versions):
    """Return the compromised version(s) that SPEC pins, as a list.

    `spec` is the text after the name, e.g. '==1.107.0', '== 1.107.*',
    '===1.107.0', '>=1,<2'. Only `==`/`===` clauses can hit (see module doc).
    """
    if not isinstance(spec, str) or not spec:
        return []
    spec = spec.split(';', 1)[0]  # environment marker
    spec = spec.split('#', 1)[0]
    hits = []
    bad = {}
    for v in bad_versions:
        rel = _release(v)
        if rel is not None:
            bad.setdefault(rel, v)
    for clause in spec.split(','):
        m = re.match(r'^\s*(===|==)\s*(\S+)\s*$', clause)
        if not m:
            continue
        op, value = m.group(1), m.group(2).strip('"\'')
        if value.endswith('.*') and op == '==':
            m2 = _VERSION_RE.match(value[:-2])
            if not m2 or m2.end() != len(value) - 2:
                continue
            pref = tuple(int(p) for p in m2.group(1).split('.'))
            for rel, orig in bad.items():
                padded = rel + (0,) * max(0, len(pref) - len(rel))
                if padded[:len(pref)] == pref and orig not in hits:
                    hits.append(orig)
            continue
        rel = _release(value)
        if rel is not None and rel in bad and bad[rel] not in hits:
            hits.append(bad[rel])
    return hits


def _artifact_pin(token):
    """(name, version) from a wheel/sdist filename or URL, else None."""
    path = re.split(r'[?#]', token, 1)[0].rstrip('/')
    base = re.split(r'[\\/]', path)[-1]
    low = base.lower()
    if low.endswith('.whl'):
        parts = base[:-4].split('-')
        if len(parts) >= 5:
            return normalize_name(parts[0]), parts[1]
        return None
    for ext in ('.tar.gz', '.zip', '.tar.bz2', '.tgz'):
        if low.endswith(ext):
            stem = base[:-len(ext)]
            if '-' in stem:
                name, ver = stem.rsplit('-', 1)
                return normalize_name(name), ver
    return None


def parse_requirement(text):
    """Parse ONE requirement string into (normalised_name, spec) or None.

    spec is the version clause text; for direct references to a wheel or sdist
    the version is read from the filename and returned as '==<version>'.
    """
    if not isinstance(text, str):
        return None
    text = text.strip().strip('"\'').strip()
    if not text or text.startswith('-'):
        return None
    if re.match(r'(?i)^(?:https?|file|git\+[a-z]+)://|^[A-Za-z]:[\\/]|^\.{0,2}[\\/]', text) or text.lower().endswith(('.whl', '.tar.gz', '.zip')):
        pin = _artifact_pin(text)
        return (pin[0], '==' + pin[1]) if pin else None
    m = _NAME_RE.match(text)
    if not m:
        return None
    name, rest = m.group(1), m.group(2).strip()
    if rest.startswith('@'):
        pin = _artifact_pin(rest[1:].strip().split(';', 1)[0].strip().strip('"\''))
        if pin and pin[0] == normalize_name(name):
            return normalize_name(name), '==' + pin[1]
        return normalize_name(name), ''
    return normalize_name(name), rest


def parse_install_args(raw):
    """Requirements from the argument text of `pip install ...`/`uv add ...`.

    Drops shell operators (but keeps parsing past them) and flags, rejoins `name == ver`
    that the shell split into separate words, and strips quotes. Words such
    as `pip`/`install` from a chained command parse as unpinned names and are
    ignored. Returns a
    list of (normalised_name, spec).
    """
    if not isinstance(raw, str):
        return []
    # Linear-time word split (shlex.read_token grows each token by string
    # concatenation and goes quadratic on one long word: 400 KB took 14 s,
    # past the 10 s PreToolUse timeout, which Claude Code treats as allow).
    # A quoted run stays inside its word; an unmatched quote is dropped.
    words = _WORD_RE.findall(raw)
    # Shell operators only separate words. Parsing continues past them so a
    # pin in a chained command (`pip install a && pip install litellm==X`)
    # is still seen: the install patterns match the FIRST install only.
    # posix=False keeps backslashes (Windows paths) and the quotes; strip them.
    tokens = [w.replace('"', '').replace("'", '') for w in words
              if w and w not in _SHELL_OPS and not set(w) <= set('&|;<>')]
    tokens = [w for w in tokens if w]
    merged = []
    for w in tokens:
        if merged and (w[:1] in _OPERATOR_CHARS + '@' or merged[-1][-1:] in _OPERATOR_CHARS + '@'):
            if not merged[-1].startswith('-'):
                merged[-1] += w
                continue
        merged.append(w)
    out = []
    skip_value = False
    for w in merged:
        if skip_value:
            skip_value = False
            continue
        if w.startswith('-'):
            # flags that take a separate value: don't mistake it for a package
            if re.match(r'^-(?:r|c|e|i|f|-requirement|-constraint|-editable|-index-url|'
                        r'-extra-index-url|-find-links|-target|-prefix|-root|-python|'
                        r'-project|-with|-with-requirements|-index|-default-index)$', w):
                skip_value = True
            continue
        req = parse_requirement(w)
        if req:
            out.append(req)
    return out


def blocked_by(requirements, pypi_versions):
    """Describe each requirement that pins a compromised version.

    `pypi_versions` maps normalised name -> {version: campaign_id}.
    """
    blocked = []
    for name, spec in requirements:
        bad = pypi_versions.get(name)
        if not bad or not spec:
            continue
        for ver in spec_hits(spec, bad):
            shown = re.sub(r'\s+', '', spec) or '==' + ver
            blocked.append(
                f"{name}{shown} (compromised PyPI version {ver}, campaign: {bad[ver]})")
    return blocked
