#!/usr/bin/env python3
"""
scan_manifest_drift.py - Manifest Drift Scanner (v1)
Detects gaps between what a package DECLARES and what it actually USES:
phantom dependencies (imported but not declared), runtime package installs,
conditional import with install fallback, and declared-but-unused deps.

Pure static analysis using AST + manifest parsing. Zero new dependencies.

Research basis:
- PylangGhost RAT (March 2026): benign manifest, evil undeclared deps
- Snyk ToxicSkills (Feb 2026): 36.8% of skills have security flaws
- Socket.dev (2025-2026): supply chain attack via phantom dependencies

Created by Alex Greenshpun
"""

import os
import bisect
import re
import ast
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "manifest_drift"

# Standard library modules (Python) - not expected in requirements
PYTHON_STDLIB = {
    'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio',
    'asyncore', 'atexit', 'base64', 'bdb', 'binascii', 'binhex',
    'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk',
    'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections',
    'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib',
    'contextvars', 'copy', 'copyreg', 'cProfile', 'crypt', 'csv',
    'ctypes', 'curses', 'dataclasses', 'datetime', 'dbm', 'decimal',
    'difflib', 'dis', 'distutils', 'doctest', 'email', 'encodings',
    'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput',
    'fnmatch', 'formatter', 'fractions', 'ftplib', 'functools', 'gc',
    'getopt', 'getpass', 'gettext', 'glob', 'grp', 'gzip', 'hashlib',
    'heapq', 'hmac', 'html', 'http', 'idlelib', 'imaplib', 'imghdr',
    'imp', 'importlib', 'inspect', 'io', 'ipaddress', 'itertools',
    'json', 'keyword', 'lib2to3', 'linecache', 'locale', 'logging',
    'lzma', 'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes',
    'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'nis', 'nntplib',
    'numbers', 'operator', 'optparse', 'os', 'ossaudiodev', 'parser',
    'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
    'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint',
    'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr',
    'pydoc', 'queue', 'quopri', 'random', 're', 'readline', 'reprlib',
    'resource', 'rlcompleter', 'runpy', 'sched', 'secrets', 'select',
    'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site',
    'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'sqlite3',
    'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct',
    'subprocess', 'sunau', 'symtable', 'sys', 'sysconfig', 'syslog',
    'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
    'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token',
    'tokenize', 'tomllib', 'trace', 'traceback', 'tracemalloc', 'tty',
    'turtle', 'turtledemo', 'types', 'typing', 'unicodedata',
    'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings', 'wave',
    'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref',
    'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib',
    # Common internal/relative import markers
    '_thread', '__future__', '_io', '_collections_abc',
}

# Node built-in modules (bare names; the "node:" prefix form is handled by
# is_node_builtin, since any "node:" specifier is a core module by definition
# and can never be an npm package).
NODE_BUILTINS = {
    'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
    'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
    'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
    'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring',
    'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls',
    'trace_events', 'tty', 'url', 'util', 'v8', 'vm', 'wasi',
    'worker_threads', 'zlib',
}  # matches require('module').builtinModules on Node 22 (bare, unprefixed)


def is_node_builtin(mod):
    """True for core modules: any node:-prefixed specifier, or a bare core name.

    Names that are core only under the node: prefix (test, sea, sqlite) are
    deliberately absent from the bare list: unprefixed they resolve to npm.
    """
    if mod.startswith('node:'):
        return True
    return mod in NODE_BUILTINS


# Runtime install patterns (critical - installs deps not in manifest)
RUNTIME_INSTALL_PATTERNS = [
    (re.compile(r'subprocess\.\w+\s*\(\s*\[?\s*["\']pip["\'],?\s*["\']install["\']'), "Runtime pip install via subprocess"),
    (re.compile(r'os\.system\s*\(\s*["\']pip\s+install'), "Runtime pip install via os.system()"),
    (re.compile(r'os\.system\s*\(\s*["\']pip3\s+install'), "Runtime pip3 install via os.system()"),
    (re.compile(r'subprocess\.\w+\s*\(\s*\[?\s*["\']npm["\'],?\s*["\']install["\']'), "Runtime npm install via subprocess"),
    (re.compile(r'os\.system\s*\(\s*["\']npm\s+install'), "Runtime npm install via os.system()"),
    (re.compile(r'subprocess\.\w+\s*\(\s*["\']pip\s+install'), "Runtime pip install via subprocess string"),
    (re.compile(r'check_call\s*\(\s*\[.*["\']pip["\'].*["\']install["\']'), "Runtime pip install via check_call"),
    (re.compile(r'check_call\s*\(\s*\[.*sys\.executable.*["\']-m["\'].*["\']pip["\']'), "Runtime pip install via sys.executable"),
]


def parse_python_requirements(repo_path):
    """Parse declared Python dependencies from requirements.txt / pyproject.toml / setup.py."""
    declared = set()

    # requirements.txt
    req_files = ['requirements.txt', 'requirements-dev.txt', 'requirements-test.txt']
    for req_name in req_files:
        req_path = os.path.join(repo_path, req_name)
        if os.path.exists(req_path):
            try:
                with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and not line.startswith('-'):
                            # Extract package name (before any version specifier)
                            pkg = re.split(r'[><=!~\[;]', line)[0].strip().lower()
                            if pkg:
                                # Normalize: underscores and hyphens are equivalent in pip
                                declared.add(pkg.replace('-', '_'))
            except (OSError, UnicodeDecodeError):
                pass

    # pyproject.toml (basic parsing)
    pyproject_path = os.path.join(repo_path, 'pyproject.toml')
    if os.path.exists(pyproject_path):
        try:
            with open(pyproject_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Match dependencies = ["pkg>=1.0", ...] pattern
            dep_matches = re.findall(r'"([a-zA-Z0-9_-]+)(?:[><=!~\[].*?)?"', content)
            for pkg in dep_matches:
                declared.add(pkg.lower().replace('-', '_'))
        except (OSError, UnicodeDecodeError):
            pass

    # setup.py (basic parsing)
    setup_path = os.path.join(repo_path, 'setup.py')
    if os.path.exists(setup_path):
        try:
            with open(setup_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            dep_matches = re.findall(r'["\']([a-zA-Z0-9_-]+)(?:[><=!~\[].*?)?["\']', content)
            for pkg in dep_matches:
                declared.add(pkg.lower().replace('-', '_'))
        except (OSError, UnicodeDecodeError):
            pass

    return declared


def parse_node_dependencies(repo_path):
    """Parse declared Node.js dependencies from package.json."""
    declared = set()
    pkg_path = os.path.join(repo_path, 'package.json')

    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            for dep_key in ('dependencies', 'devDependencies', 'peerDependencies',
                            'optionalDependencies'):
                if dep_key in data and isinstance(data[dep_key], dict):
                    for pkg in data[dep_key]:
                        declared.add(pkg.lower())
        except (OSError, json.JSONDecodeError, AttributeError):
            pass

    return declared


def _own_package_name(repo_path):
    """Lowercased package.json "name", only when the package can resolve
    itself.

    Node resolves `import 'name'` to the package's own files only through a
    self-referencing "exports" map. Without one it resolves to
    node_modules/<name>, which can be a different (planted) package, so no
    exemption is granted.
    """
    try:
        with open(os.path.join(repo_path, 'package.json'), 'r',
                  encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        name = data.get('name')
        if isinstance(name, str) and data.get('exports'):
            return name.lower()
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    return None


class ImportExtractor(ast.NodeVisitor):
    """Extract all import statements from Python AST."""

    def __init__(self):
        self.imports = set()  # Set of top-level module names

    def visit_Import(self, node):
        for alias in node.names:
            top_module = alias.name.split('.')[0]
            self.imports.add(top_module.lower())
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            top_module = node.module.split('.')[0]
            if node.level == 0:  # Skip relative imports
                self.imports.add(top_module.lower())
        self.generic_visit(node)


def extract_python_imports(file_path):
    """Extract imported module names from a Python file using AST."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source)
        extractor = ImportExtractor()
        extractor.visit(tree)
        return extractor.imports
    except (OSError, SyntaxError, ValueError, RecursionError):
        return set()


# ECMAScript WhiteSpace + LineTerminator, explicit (str.isspace() is wrong both ways:
# it misses U+FEFF and accepts U+001C-001F / U+0085, which Node rejects).
_JS_WS_CHARS = frozenset('\t\x0b\x0c \xa0\u1680\u202f\u205f\u3000\ufeff\n\r\u2028\u2029') | frozenset(
    chr(c) for c in range(0x2000, 0x200b))
_TOK_RE = re.compile(
    r"[\t\x0b\x0c \xa0\u1680\u2000-\u200a\u202f\u205f\u3000\ufeff\n\r\u2028\u2029]+|[A-Za-z_$][\w$]*|\d[\w.]*|//[^\n\r\u2028\u2029]*|/\*|\+\+|--|.", re.S)
# Hard keywords after which a `/` is a regex. Contextual words (of, in, new,
# instanceof) are ambiguous and raise doubt instead; a keyword used as a
# property name (`obj.return / 2`) is an ordinary identifier.
_REGEX_KEYWORDS = frozenset((
    'return', 'typeof', 'case', 'delete', 'void', 'throw', 'else', 'do',
    'yield', 'await', 'default', 'extends'))
_DOUBT_WORDS = frozenset(('in', 'of', 'new', 'instanceof'))
_WALK_MAX_CHARS = 2_000_000


_GENERIC_ARROW_RE = re.compile(
    r'<[A-Za-z_$][\w$]*(?:\s+extends\s[^<>=\n]*|\s*,[^<>(\n]*)?>\s*\([^()\n]*\)\s*(?::[^=\n]*)?=>')
_JSX_TEXT_RE = re.compile(r'<[A-Za-z_$>][^<>\n]*>[^<\n]*(?://|/\*)')


def _comment_spans(content):
    """Comment spans both readings agree on, up to the first point where
    either reading doubts or the two readings disagree. One reading treats a
    single `/` as a regex where the previous token allows it, the other treats
    every single `/` as division; a lexer desync cannot be laundered by a later
    repair because the two desync differently. Everything from the first
    doubt or disagreement onward gets no suppression (fail open)."""
    sa, da = _walk_partial(content, True)
    sb, db = _walk_partial(content, False)
    cut = min(x for x in (da, db, len(content) + 1) if x is not None)
    out = []
    for x, y in zip(sa, sb):
        if x != y:
            cut = min(cut, x[0], y[0])
            break
    sb_set = set(sb)
    for sp in sa:
        if sp[1] < cut and sp in sb_set:
            out.append(sp)
    return out


def _comment_spans_mode(content, regex_mode):
    """Spans from one reading, or [] when that reading doubts anywhere."""
    spans, doubt = _walk_partial(content, regex_mode)
    return [] if doubt is not None else spans


def _walk_partial(content, regex_mode):
    """Spans (start, end) of real comments, from one lexical walk of the file
    (code, line/block comment, quoted strings, templates with ${} nesting,
    regex literals). Returns [] whenever the walk meets anything it cannot be
    sure about (a `/` after `)`, `}` or `++`/`--`, a string broken by a
    newline, over-deep templates, oversized input): suppression is only ever
    granted from a walk with no doubt, so misses are never the failure mode."""
    n = len(content)
    if n > _WALK_MAX_CHARS:
        return [], 0
    if ('//' not in content and '/*' not in content and '<!--' not in content
            and '-->' not in content and not content.startswith('#!')):
        return [], None
    spans = []
    last = [0]
    seen = [False]  # any code token yet (line-start test for `-->` / `<!--`)

    def string_end(i, q):
        while i < n:
            c = content[i]
            if c == '\\':
                i += 2
                continue
            if c == q:
                return i + 1
            if c in '\n\r':
                return -1
            i += 1
        return -1

    def regex_end(i):
        in_cls = False
        i += 1
        while i < n:
            c = content[i]
            if c == '\\':
                i += 2
                continue
            if c in '\n\r':
                return -1
            if in_cls:
                if c == ']':
                    in_cls = False
            elif c == '[':
                in_cls = True
            elif c == '/':
                return i + 1
            i += 1
        return -1

    def walk(i, depth, in_template_expr):
        """Walk code from i. Returns the index after the closing `}` of a
        ${...} when in_template_expr, else n. -1 signals doubt."""
        if depth > 40:
            return -1
        prev = 'op'
        braces = 0
        jsxish = '</' in content or '/>' in content or '<>' in content
        nl = False  # a line break since the last token (ASI-ambiguity)
        while i < n:
            last[0] = i
            m = _TOK_RE.match(content, i)
            tok = m.group(0)
            j = m.end()
            c = tok[0]
            if c in _JS_WS_CHARS:
                if '\n' in tok or '\r' in tok or '\u2028' in tok or '\u2029' in tok:
                    nl = True
                i = j
                continue
            if ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f:
                return -1  # a control char Node rejects as whitespace: doubt
            was_nl = nl
            if content.startswith('<!--', i) or (
                    content.startswith('-->', i) and (was_nl or not seen[0])):
                # Annex B HTML-like comments (Node runs them in CommonJS): a
                # line-start `<!--` or `-->` is a whole-line comment; a
                # mid-line `<!--` is ambiguous, so doubt.
                if content.startswith('<!--', i) and not (was_nl or not seen[0]):
                    return -1
                e0 = _LINE_END_RE.search(content, i)
                e0 = e0.start() if e0 else n
                spans.append((i, e0))
                i = e0
                continue
            if tok.startswith('//'):
                spans.append((i, j))
                i = j
                continue
            if tok == '/*':
                close = content.find('*/', j)
                end = n if close == -1 else close + 2
                spans.append((i, end))
                if re.search('[\\n\\r\\u2028\\u2029]', content[i:end]):
                    nl = True
                i = end
                continue
            nl = False
            seen[0] = True
            if c.isalpha() or c in '_$':
                if prev == 'dot':
                    prev = 'id'
                elif tok in _DOUBT_WORDS:
                    prev = 'amb'
                else:
                    prev = 'op' if tok in _REGEX_KEYWORDS else 'id'
                i = j
                continue
            if c.isdigit():
                prev = 'id'
                i = j
                continue
            if tok in ('++', '--'):
                prev = 'amb'
                i = j
                continue
            if c in '\'"':
                e = string_end(i + 1, c)
                if e == -1:
                    return -1
                prev = 'id'
                i = e
                continue
            if c == '`':
                e = template_end(i + 1, depth + 1)
                if e == -1:
                    return -1
                prev = 'id'
                i = e
                continue
            if c == '<' and (prev in ('op', 'amb') or (jsxish and prev in (')', '}'))) and j < n and (
                    content[j].isalpha() or content[j] in '>_$') and \
                    ((jsxish and not _GENERIC_ARROW_RE.match(content, i))
                     or _JSX_TEXT_RE.match(content, i)):
                return -1  # JSX/type-assertion text after an operator: doubt
            if c == '/':
                if was_nl and prev in ('id', ']', ')', '}', 'amb'):
                    return -1  # ASI: a slash after a line break may start a regex
                if prev in ('id', ']'):
                    prev = 'op'
                    i = j
                    continue
                if prev in ('amb', ')', '}'):
                    return -1
                if not regex_mode:
                    prev = 'op'
                    i = j
                    continue
                if j < n and content[j] in ' \t':
                    return -1  # a regex starting with whitespace: doubt
                e = regex_end(i)
                if e == -1:
                    return -1
                prev = 'id'
                i = e
                continue
            if c == '{':
                braces += 1
                prev = 'op'
            elif c == '}':
                if in_template_expr and braces == 0:
                    return j
                braces -= 1
                prev = '}'
            elif c == ')':
                prev = ')'
            elif c == ']':
                prev = ']'
            elif c == '.':
                prev = 'dot'
            elif c == '*' and content.startswith('*/', i):
                return -1  # `*/` outside any comment: doubt
            else:
                prev = 'op'
            i = j
        return -1 if in_template_expr else n

    def template_end(i, depth):
        while i < n:
            c = content[i]
            if c == '\\':
                i += 2
                continue
            if c == '`':
                return i + 1
            if c == '$' and content.startswith('${', i):
                i = walk(i + 2, depth, True)
                if i == -1:
                    return -1
                continue
            i += 1
        return -1

    if content.startswith('\ufeff#!'):
        return [], 0  # BOM before a hashbang: engines disagree, so no suppression
    start = 0
    if content.startswith('#!'):  # hashbang: a whole-line comment, offset 0 only
        m0 = _LINE_END_RE.search(content)
        start = m0.start() if m0 else n
        spans.append((0, start))
    if walk(start, 0, False) == -1:
        return spans, last[0]
    return spans, None


# JS line terminators: LF, CR, U+2028, U+2029 (a // comment ends at any of them).
_LINE_END_RE = re.compile('[\\n\\r\\u2028\\u2029]')


def extract_js_imports(file_path):
    """Extract imported module names from JS/TS files using regex."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return set()

    imports = set()

    # Module names must be valid npm identifier shapes; the regexes below can
    # capture garbage spans from mid-code 'from'/'require' text (schema
    # builders, template literals), which previously surfaced as phantom-dep
    # titles containing newlines and punctuation.
    def _valid(mod):
        if mod.startswith('node:'):
            return re.fullmatch(r'node:[a-z0-9][a-z0-9._~-]*', mod) is not None
        return re.match(
            r'^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$', mod
        ) is not None and len(mod) <= 214

    def _add(mod):
        if mod.startswith('.'):  # relative import
            return
        # Package name (scoped: @scope/pkg, unscoped: pkg/sub -> pkg)
        if mod.startswith('@'):
            parts = mod.split('/')
            if len(parts) >= 2:
                imports.add('/'.join(parts[:2]).lower())
        else:
            imports.add(mod.split('/')[0].lower())

    # Whitespace or block comments between tokens: `require(/*c*/'m')` is a
    # real import. The comment form is linear (no nested .*? backtracking).
    ws = r'(?:[\t\x0b\x0c \xa0\u1680\u2000-\u200a\u202f\u205f\u3000\ufeff\n\r\u2028\u2029]|/\*(?:[^*]|\*(?!/)){0,300}\*/)*'
    # A string or an interpolation-free template literal.
    spec = (r'(?:"([^"\\\n]{1,214})"|\'([^\'\\\n]{1,214})\''
            r'|`((?:[^`\\\n$]|\$(?!\{)){1,214})`)')

    call_tail = r'(?:\(' + ws + r')*' + spec  # require(/** @type {string} */ ("m"))

    _spans = []

    def _in_comment(pos):
        """True when one lexical walk of the whole file puts pos inside a real
        comment (doubt anywhere in the file means never)."""
        if not _spans:
            sp = _comment_spans(content)
            _spans.append(sp)
            _spans.append([x[0] for x in sp])
        k = bisect.bisect_right(_spans[1], pos) - 1
        return k >= 0 and pos < _spans[0][k][1]

    def _collect(pattern, flags=0, text=None):
        for m in re.finditer(pattern, content if text is None else text, flags):
            if _in_comment(m.start()):
                continue
            mod = next((g for g in m.groups() if g), None)
            if mod:
                _add(mod)

    req = r'(?:\bmodule\s*\.\s*)?\brequire'
    # require('m'), module.require('m')
    _collect(req + ws + r'\(' + ws + call_tail)
    # require.call(null, 'm'), require.apply is array-based and not matched
    _collect(r'\brequire' + ws + r'\.' + ws + r'call' + ws + r'\(' + ws
             + r'[\w$.]+' + ws + r',' + ws + call_tail)
    # (0, require)('m'), (0, module.require)('m')
    _collect(r'\(' + ws + r'[\w$.]+' + ws + r',' + ws + r'(?:module\s*\.\s*)?require'
             + ws + r'\)' + ws + r'\(' + ws + call_tail)
    # createRequire(import.meta.url)('m')
    _collect(r'\bcreateRequire' + ws + r'\([^()]{0,200}\)' + ws + r'\(' + ws + call_tail)
    # const r = require; r('m')
    _aliases = set()
    for am in re.finditer(
            r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:(?:module\s*\.\s*)?require|createRequire\s*\([^()]{0,200}\))\s*(?=[;,\n)]|$)',
            content):
        if am.group(1) in _aliases or len(_aliases) >= 16:
            continue
        _aliases.add(am.group(1))
        _collect(r'(?<![\w$.])' + re.escape(am.group(1)) + ws + r'\(' + ws + call_tail)

    # Declaration files get no special treatment: Node runs a required .d.ts
    # as JS, and every suffix, comment or `type` carve-out proved evadable.
    # Type-only imports there are an accepted WARN-direction false positive.
    _collect(r'(?<![\w$.])import' + ws + r'\(' + ws + call_tail)

    # Static import/export ... from 'm', across lines. The clause cannot hold
    # quotes or semicolons. To stay linear without a length cap, each maximal
    # quote-free run is examined once: every start inside one run shares the
    # same candidate `from`, so later starts in a run are skipped.
    start_re = re.compile(r'(?m)(?:^|(?<=[;{}])|(?<=\*/))[ \t]*(?:import|export)\b')
    plain_re = re.compile(r'[^\'"`;/]*')
    from_re = re.compile(r'\bfrom')
    tail_re = re.compile(ws + spec)
    no_more_close = [False]  # once one `*/` search fails, none later can pass

    def _scan_clause(i):
        """Walk one statement clause. Comments (block and line) are skipped
        whole, so quotes or a decoy `from 'x'` inside them are invisible.
        Returns (end_position, [positions just after each real `from`])."""
        n = len(content)
        froms = []
        while i < n:
            m_ = plain_re.match(content, i)
            for fm in from_re.finditer(content, i, m_.end()):
                froms.append(fm.end())
            i = m_.end()
            if i >= n:
                break
            if content.startswith('/*', i):
                j = -1 if no_more_close[0] else content.find('*/', i + 2)
                if j == -1:
                    no_more_close[0] = True
                    break
                i = j + 2
            elif content.startswith('//', i):
                lm = _LINE_END_RE.search(content, i)
                if not lm:
                    return n, froms
                i = lm.start()
            elif content[i] == '/':
                i += 1
            else:
                break
        return i, froms

    pos = 0
    while True:
        sm = start_re.search(content, pos)
        if not sm:
            break
        # Suppress an anchor only when one lexical walk of the whole file
        # (strings, templates, regex literals, comments) puts it inside a
        # comment. Doubt anywhere in the file means no suppression at all.
        if _in_comment(sm.start()):
            pos = sm.end()
            continue
        end, froms = _scan_clause(sm.end())
        for f_end in reversed(froms):
            tm = tail_re.match(content, f_end)
            if tm:
                mod = next((g for g in tm.groups() if g), None)
                if mod:
                    _add(mod)
                break
        pos = max(end, sm.end())
    # Bare side-effect import 'm'
    _collect(r'(?m)(?:^|(?<=[;{}])|(?<=\*/))[ \t]*import' + ws + spec)

    imports = {m for m in imports if _valid(m)}
    # Conservative overflow: a call whose comment padding exceeds the bounded
    # gap cannot be parsed; report a marker instead of deciding "absent".
    open_re = re.compile(
        r'(?<![\w$.])(?:module\s*\.\s*)?(?:require|import)\s*\(()(?=\s*/\*)'
        r'|\bcreateRequire\s*\([^()]{0,200}\)\s*\(()(?=\s*/\*)'
        r'|\brequire\s*\.\s*call\s*\(\s*[\w$.]+\s*,()(?=\s*/\*)'
        r'|\(\s*[\w$.]+\s*,\s*(?:module\s*\.\s*)?require\s*\)\s*\(()(?=\s*/\*)')
    for om in open_re.finditer(content):
        end = max(g for g in (om.end(1), om.end(2), om.end(3), om.end(4)))
        if not re.compile(ws + call_tail).match(content, end):
            imports.add('unparsed-comment-padded-import')
            break
    return imports



def detect_conditional_install(file_path, rel_path):
    """Detect try/except import with install fallback pattern."""
    if not file_path.endswith('.py'):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    findings = []

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return []

    source_lines = source.split('\n')

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            # Check if body has an import
            has_import = False
            for item in node.body:
                if isinstance(item, (ast.Import, ast.ImportFrom)):
                    has_import = True
                    break

            if not has_import:
                continue

            # Check if any exception handler has pip install or os.system
            for handler in node.handlers:
                handler_src = ast.get_source_segment(source, handler) if hasattr(ast, 'get_source_segment') else ''
                if not handler_src:
                    # Fallback: check lines in range
                    start = getattr(handler, 'lineno', 0)
                    end = getattr(handler, 'end_lineno', start + 5)
                    handler_src = '\n'.join(source_lines[start - 1:end]) if start > 0 else ''

                if re.search(r'pip\s+install|subprocess|os\.system|check_call.*install', handler_src):
                    lineno = getattr(node, 'lineno', 0)
                    snippet = source_lines[lineno - 1].strip()[:120] if lineno > 0 and lineno <= len(source_lines) else ''
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME, severity="critical",
                        title="Conditional Import with Install Fallback",
                        description="try/except import pattern that installs packages on failure. Package not declared in manifest.",
                        file=rel_path, line=lineno,
                        snippet=snippet,
                        category="runtime-install"
                    ))

    return findings


# Common dist-name <-> import-name aliases. Some packages ship under a
# different name than their import module (e.g. `import yaml` is provided by
# the `pyyaml` distribution; `import cv2` by `opencv-python`). When the
# *distribution* name is declared in the manifest we should not flag the
# import as a phantom dependency. Star patterns (e.g. "google-*") match
# against any distribution starting with the literal prefix.
DIST_ALIASES = {
    "yaml": "pyyaml",
    "cv2": "opencv-python",
    "pil": "pillow",
    "skimage": "scikit-image",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "attr": "attrs",
    "gi": "pygobject",
    "Crypto": "pycryptodome",
    "OpenSSL": "pyopenssl",
    "gi.repository": "pygobject",
    "google": "google-*",
    "flask_sqlalchemy": "flask-sqlalchemy",
    "flask_login": "flask-login",
    "flask_wtf": "flask-wtf",
    "flask_restful": "flask-restful",
    "jwt": "pyjwt",
    "MySQLdb": "mysqlclient",
    "pandas": "pandas",
    "numpy": "numpy",
    "serial": "pyserial",
    "wx": "wxpython",
}


def _alias_distribution_resolved(import_name, py_declared):
    """Return True if an import that looks like a phantom dependency is in
    fact covered by a declared distribution via a known alias map (e.g.
    `import yaml` is satisfied by `PyYAML` in requirements). Case-insensitive.
    """
    alias = DIST_ALIASES.get(import_name)
    if alias is None:
        return False
    if alias.endswith("-*"):
        prefix = alias[:-2].lower()
        return any(name.lower().startswith(prefix) for name in py_declared)
    return alias.lower() in py_declared


def _collect_local_module_roots(repo_path):
    """Return a set of top-level module names that resolve to project-local
    code and therefore must NOT be flagged as phantom dependencies.

    Rules (Issue #38):
      - any top-level directory (no '__init__.py' required since we cannot
        safely assume the user keeps it; we test on import name presence)
        - any top-level '<name>.py' file
      - the project's own distribution name from pyproject.toml / setup.py
    """
    locals_ = set()
    try:
        with os.scandir(repo_path) as it:
            for entry in it:
                if not entry.is_dir(follow_symlinks=False) and not entry.is_file(follow_symlinks=False):
                    continue
                name = entry.name
                if name.startswith('.') or name.startswith('_'):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    # A directory may be a Python package if it has __init__.py
                    # immediately inside, otherwise the import may still be a
                    # local module via namespace packages. Be conservative:
                    # include the directory name when __init__.py is present;
                    # also include sub-directory names so nested packages
                    # resolve (e.g. "mypkg" under src/).
                    locals_.add(name.lower())
                else:
                    base, ext = os.path.splitext(name)
                    if ext == '.py':
                        locals_.add(base.lower())
    except (OSError, PermissionError):
        pass

    # Project's own distribution name (pyproject.toml or setup.py)
    pyproject_path = os.path.join(repo_path, 'pyproject.toml')
    if os.path.exists(pyproject_path):
        try:
            with open(pyproject_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            m = re.search(r'(?im)^\s*name\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                locals_.add(m.group(1).strip().lower().replace('-', '_'))
        except (OSError, UnicodeDecodeError):
            pass

    setup_path = os.path.join(repo_path, 'setup.py')
    if os.path.exists(setup_path):
        try:
            with open(setup_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            m = re.search(r'(?im)^\s*name\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                locals_.add(m.group(1).strip().lower().replace('-', '_'))
        except (OSError, UnicodeDecodeError):
            pass

    return locals_


def scan_manifest_drift(repo_path):
    """Compare declared vs actual dependencies. Return findings.

    Issue #38 changes:
      - Imports carry PROVENANCE: each module maps to the list of importer
        rel_paths that brought it in, so we can emit one finding per phantom
        pkg with the real importer location (not a synthetic
        "(multiple files)" aggregate).
      - Local first-party modules (top-level dirs/<name>.py and the project's
        own distribution name) are excluded from "phantom" before they can
        pollute the count.
      - Common dist-name aliases (`import yaml` => `pyyaml`, etc.) are
        suppressed when the mapped distribution is declared.
    """
    findings = []

    # Collect declared deps
    py_declared = parse_python_requirements(repo_path)
    js_declared = parse_node_dependencies(repo_path)

    # No manifest files at all? Skip drift analysis (nothing to compare against)
    has_py_manifest = bool(py_declared) or any(
        os.path.exists(os.path.join(repo_path, f))
        for f in ('requirements.txt', 'pyproject.toml', 'setup.py')
    )
    has_js_manifest = bool(js_declared) or os.path.exists(os.path.join(repo_path, 'package.json'))

    # Local-first-party module roots that must NOT be flagged as phantom.
    local_roots = _collect_local_module_roots(repo_path)

    # Collect actual imports WITH provenance (module name -> list of importers).
    py_imported = {}     # type: dict[str, list[str]]
    js_imported = {}     # type: dict[str, list[str]]

    ignore_patterns = core.load_ignore_patterns(repo_path)
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.py':
            for mod in extract_python_imports(file_path):
                py_imported.setdefault(mod, []).append(rel_path)
        elif ext in ('.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'):
            for mod in extract_js_imports(file_path):
                js_imported.setdefault(mod, []).append(rel_path)

    py_imported_set = set(py_imported.keys())
    js_imported_set = set(js_imported.keys())

    # Python: phantom deps (imported but not declared)
    if has_py_manifest:
        py_phantom = py_imported_set - py_declared - PYTHON_STDLIB
        # Filter out relative/local imports (single underscore prefix is okay)
        py_phantom = {p for p in py_phantom if not p.startswith('_') and len(p) > 1}
        # Filter out local first-party modules
        py_phantom = {p for p in py_phantom if p not in local_roots}
        # Filter out alias-resolved modules (declared under a different dist name)
        py_phantom = {p for p in py_phantom if not _alias_distribution_resolved(p, py_declared)}
        for pkg in sorted(py_phantom):
            importers = py_imported.get(pkg, [])
            first_importer = importers[0] if importers else "<unknown>"
            importer_count = len(importers)
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"Phantom Dependency: {pkg}",
                description=(
                    f"Module '{pkg}' is imported in code but not declared in "
                    f"requirements/pyproject. Could be a shadow dependency. "
                    f"Imported from {importer_count} location"
                    f"{'s' if importer_count != 1 else ''}; first seen in "
                    f"{first_importer}."
                ),
                file=first_importer, line=0,
                snippet=f"import {pkg} (not in manifest)",
                category="phantom-dependency"
            ))

    # JavaScript: phantom deps (imported but not declared)
    if has_js_manifest:
        own_name = _own_package_name(repo_path)
        js_phantom = {m for m in js_imported_set - js_declared
                      if not is_node_builtin(m) and m != own_name}
        for pkg in sorted(js_phantom):
            importers = js_imported.get(pkg, [])
            first_importer = importers[0] if importers else "<unknown>"
            importer_count = len(importers)
            findings.append(core.Finding(
                scanner=SCANNER_NAME, severity="high",
                title=f"Phantom Dependency: {pkg}",
                description=(
                    f"Module '{pkg}' is required/imported but not in "
                    f"package.json. Could be a shadow dependency. Imported "
                    f"from {importer_count} location"
                    f"{'s' if importer_count != 1 else ''}; first seen in "
                    f"{first_importer}."
                ),
                file=first_importer, line=0,
                snippet=f"require('{pkg}') / import '{pkg}' (not in manifest)",
                category="phantom-dependency"
            ))

    # Declared but never imported (potential confusion decoy)
    if has_py_manifest and py_imported_set:
        py_unused = py_declared - py_imported_set - {'setuptools', 'wheel', 'pip', 'build', 'twine', 'pytest', 'black', 'flake8', 'mypy', 'ruff', 'isort', 'pylint'}
        for pkg in sorted(py_unused):
            if pkg and not pkg.startswith('_'):
                findings.append(core.Finding(
                    scanner=SCANNER_NAME, severity="low",
                    title=f"Declared but Unused: {pkg}",
                    description=f"Package '{pkg}' declared in manifest but never imported. Could be a dependency confusion decoy.",
                    file="requirements", line=0,
                    snippet=f"{pkg} in manifest, no import found",
                    category="unused-dependency"
                ))

    return findings


def scan_runtime_installs(repo_path):
    """Detect runtime package installation patterns."""
    findings = []

    ignore_patterns = core.load_ignore_patterns(repo_path)
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ('.py', '.js', '.ts', '.sh'):
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            continue

        findings.extend(core.scan_patterns(
            content, rel_path, RUNTIME_INSTALL_PATTERNS,
            "runtime-install", "critical", SCANNER_NAME
        ))

        # Conditional import + install (Python AST-based)
        findings.extend(detect_conditional_install(file_path, rel_path))

    return findings


def scan_file(file_path, rel_path):
    """Scan a single file for runtime install patterns only.
    Manifest drift is repo-level, handled by scan_manifest_drift()."""
    findings = []

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ('.py', '.js', '.ts', '.sh'):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return []

    findings.extend(core.scan_patterns(
        content, rel_path, RUNTIME_INSTALL_PATTERNS,
        "runtime-install", "critical", SCANNER_NAME
    ))

    findings.extend(detect_conditional_install(file_path, rel_path))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Manifest Drift Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning {repo_path} for manifest drift...")

    all_findings = []

    # Repo-level: declared vs actual dependency comparison
    all_findings.extend(scan_manifest_drift(repo_path))

    # File-level: runtime install patterns + conditional imports
    all_findings.extend(scan_runtime_installs(repo_path))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
