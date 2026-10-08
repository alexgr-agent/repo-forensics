#!/usr/bin/env python3
"""
scan_entrypoint.py - Entrypoint Payload Injection Scanner (scanner #20)
Detects payloads injected into a repo's OWN source entrypoints that execute
on require()/import. Targets tampered repo code, NOT dependency entrypoints
(node_modules/ is excluded from walks). The IOC version-pinning in
compromised_versions.json handles the dependency case.

Two detection strategies:
  1. JavaScript CJS entrypoint injection (node-ipc pattern):
     - IIFE appended at end of file after legitimate exports
     - High-entropy blocks appended after last export
     - module.exports reassignment at file bottom

  2. Python import-time execution (durabletask pattern):
     - Top-level dangerous calls in __init__.py / setup.py
     - Uses Python AST to scope only to module body (outside FunctionDef/ClassDef)

Categories: entrypoint-iife, entrypoint-import-exec
Deduplication: distinct categories avoid double-firing with scan_sast/detect_trifecta_raw.

Created by Alex Greenshpun
"""

import os
import re
import sys
import ast
import json
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core

SCANNER_NAME = "entrypoint"

# ---------------------------------------------------------------------------
# JavaScript CJS entrypoint injection detection
# ---------------------------------------------------------------------------

# Build tool banner comments that indicate a bundled/minified artifact,
# not a hand-tampered entrypoint. These are legitimate IIFEs.
_BUILD_TOOL_BANNERS = re.compile(
    r'(?:'
    r'/\*[*!]?\s*(?:webpack|rollup|esbuild|parcel|vite|browserify|uglify|terser|babel|swc)\b'
    r'|//\s*(?:webpack|rollup|esbuild|parcel|vite|browserify|uglify|terser|babel|swc)\b'
    r'|/\*!\s*bundled\b'
    r'|@license\b'
    r'|@preserve\b'
    r')',
    re.IGNORECASE,
)

# IIFE patterns at end of file. Captures the IIFE body for content analysis.
# Matches: (function(){...})() and (()=>{...})() with optional semicolons/whitespace
_IIFE_PATTERN = re.compile(
    r'(?:'
    r'\(\s*function\s*\([^)]*\)\s*\{' r'|'  # (function(){
    r'\(\s*\(\s*\)\s*=>\s*\n?\s*\{'          # (()=>{ or (()=>\n{
    r')',
)

# Dangerous patterns inside IIFE bodies that escalate to CRITICAL
_IIFE_DANGEROUS_PATTERNS = [
    (re.compile(r"require\s*\(\s*['\"]child_process['\"]"), "require('child_process')"),
    (re.compile(r"require\s*\(\s*['\"]net['\"]"), "require('net')"),
    (re.compile(r"require\s*\(\s*['\"]http['\"]"), "require('http')"),
    (re.compile(r"require\s*\(\s*['\"]https['\"]"), "require('https')"),
    (re.compile(r"require\s*\(\s*['\"]dgram['\"]"), "require('dgram')"),
    (re.compile(r"require\s*\(\s*['\"]dns['\"]"), "require('dns')"),
    (re.compile(r"require\s*\(\s*['\"]fs['\"]"), "require('fs')"),
    (re.compile(r'\bprocess\s*(?:\.\s*env\b|\[\s*[\'"]env[\'"]\s*\])'), "process.env access"),
    (re.compile(r'\bexecSync\b'), "execSync call"),
    (re.compile(r'\bspawnSync\b'), "spawnSync call"),
    (re.compile(r'\beval\s*\('), "eval() call"),
    (re.compile(r'\bnew\s+Function\s*\('), "new Function() call"),
    (re.compile(r'\bfetch\s*\(\s*[\'"]https?://'), "fetch() to external URL"),
    (re.compile(r'\bXMLHttpRequest\b'), "XMLHttpRequest"),
]

# module.exports reassignment: detects a second module.exports = ... at bottom
_MODULE_EXPORTS_RE = re.compile(r'^\s*module\.exports\s*=', re.MULTILINE)

# High-entropy detection for appended obfuscated content
_HEX_BLOCK = re.compile(r'[0-9a-fA-F]{40,}')
_BASE64_BLOCK = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

CJS_EXTENSIONS = {'.js', '.cjs', '.mjs'}


def _shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


_EXPORT_DEFAULT_PREFIX_RE = re.compile(r'^[ \t]*export\s+default\s*$')
_MAX_IIFE_MATCHES = 100
# A skipped comment holding ')' followed by any call or member-access opener
# ( '(' '[' backtick '?.' '.call' '.apply' '.bind' ) may really be a regex literal hiding the invocation:
# fail closed. Plain prose parentheses do not trip it.
# Allow-list for the one benign env shape in an uninvoked factory: a named
# variable compared with a string literal (`process.env.NODE_ENV !== 'production'`).
# Every `process.env` occurrence must match; anything else (bare object, computed
# member, concatenation, call argument, destructuring) stays critical. A
# deny-list of exfil primitives loses to any spelling it did not list.
_ENV_GATE_RE = re.compile(
    r"""process\s*\.\s*env\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:===?|!==?)\s*(?:'[^'\\\n]*'|"[^"\\\n]*")"""
    r"""|(?:'[^'\\\n]*'|"[^"\\\n]*")\s*(?:===?|!==?)\s*process\s*\.\s*env\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?![\w$(\[.])""")
# Pure existence tests of `process` (cannot carry data anywhere).
_ENV_TRUTH_RE = re.compile(
    r"\b(?:if|while)\s*\(\s*!?\s*process\s*\.\s*env\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"
    r"|!\s*process\s*\.\s*env\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?![\w$(\[.])")
# Pure existence tests of `process` (cannot carry data anywhere).
_PROCESS_GUARD_RE = re.compile(
    r"""!\s*process\s*\|\||\bprocess\s*&&(?!\s*process\s*[.\[])|typeof\s+process\s*(?:!==?|===?)\s*['"]\w+['"]""")


def _env_only_gates(region):
    """True when the region's only env references are literal-comparison gates."""
    if not re.search(r'\bprocess\s*(?:\.\s*env\b|\[\s*[\'"]env[\'"]\s*\])', region):
        return True
    covered = 0
    for m in _ENV_GATE_RE.finditer(region):
        covered += len(re.findall(r'\bprocess\b', m.group(0)))
    for m in _ENV_TRUTH_RE.finditer(region):
        covered += len(re.findall(r'\bprocess\b', m.group(0)))
    for m in _PROCESS_GUARD_RE.finditer(region):
        covered += len(re.findall(r'\bprocess\b', m.group(0)))
    return covered == len(re.findall(r'\bprocess\b', region))
# A raw `})(`, `}).call`, `}).apply`, `}).bind`, `})?.`, `})[` or `})` + backtick
# anywhere after the factory start, whatever the string/regex/comment state,
# withdraws the uninvoked-factory carve-out. It runs on the raw text and on a
# copy with comments naively removed (string-unaware, so `})/**/()` and
# `})\n//x\n()` cannot hide the call), independent of the quote-aware walk.
_RAW_INVOKE_RE = re.compile(
    r'\}[\s\ufeff]*\)[\s\ufeff]*(?:\(|\[|\.[\s\ufeff]*(?:call|apply|bind)\b|\?\.|`)')
_NAIVE_COMMENT_RE = re.compile(r'/\*.*?\*/|//[^\n\r\u2028\u2029]*', re.S)


def _raw_invoked(text, start):
    tail = text[start:]
    if _RAW_INVOKE_RE.search(tail):
        return True
    return bool(_RAW_INVOKE_RE.search(_NAIVE_COMMENT_RE.sub(' ', tail)))


_ANY_PAREN_RE = re.compile(r'\)')
_CALL_TOKEN_RE = re.compile(r'\)\s*(?:[(\[`]|\?\.|\.\s*(?:call|apply|bind)\b)')
def _only_trailing_noise(text, i):
    """True when text[i:] is only whitespace, one optional `;` and comments.
    Linear scan (a backtracking regex here is quadratic on long whitespace)."""
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    if i < n and text[i] == ';':
        i += 1
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith('/*', i):
            e = text.find('*/', i + 2)
            if e == -1:
                return False
            i = e + 2
        elif text.startswith('//', i):
            e = text.find('\n', i)
            i = n if e == -1 else e
        else:
            return False
    return True


def _comment_is_suspect(text, start, end, is_line):
    """True when a skipped comment span might really be a regex literal that
    hides an invocation. A comment on its own line (nothing but whitespace
    before it, and for block comments nothing but whitespace after it) is
    ordinary documentation: only call-shaped text trips it. Anywhere else, any
    `)` fails closed, so `)` followed by an operator cannot slip through."""
    ls = text.rfind('\n', 0, start) + 1
    own_line = text[ls:start].strip() == ''
    if own_line and not is_line:
        le = text.find('\n', end)
        own_line = text[end:(len(text) if le == -1 else le)].strip() == ''
    if own_line:
        return bool(_CALL_TOKEN_RE.search(text, start, end))
    return bool(_ANY_PAREN_RE.search(text, start, end))


def _is_uninvoked_default_export(text, start):
    """True for a whole `export default (function|arrow ...)` factory value.

    ESM plugin factories (dayjs plugins, for example) export a function
    expression wrapped in parens. That is a value, not a self-executing IIFE.
    Deliberately narrow and allow-list based:
      - `export default` must be the only thing before the paren on its line;
      - the matching close paren must be followed by nothing except an
        optional `;`, whitespace and comments through the end of the file, so
        any call form (`()`, `.call`, `.bind(..)()`, `?.()`, `['call']()`,
        a comment then `(`) leaves it flagged;
      - anything that cannot be balanced stays flagged.
    """
    line_start = text.rfind('\n', 0, start) + 1
    if not _EXPORT_DEFAULT_PREFIX_RE.match(text[line_start:start]):
        return False
    depth = 0          # paren depth, the outer `(` is depth 1
    braces = 0         # brace depth inside the factory
    body_closed = False  # function body finished at paren depth 1
    quote = None
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == '\\':
                i += 1
            elif ch == quote:
                quote = None
            elif ch == '\n' and quote != '`':
                # A '/" string cannot span lines without a backslash: this
                # is a regex literal (e.g. /'/) desyncing quote tracking.
                return False
        elif ch in ('"', "'", '`'):
            quote = ch
        elif ch == '/' and text.startswith('//', i):
            j = text.find('\n', i)
            if _comment_is_suspect(text, i, n if j == -1 else j, True):
                return False
            i = n if j == -1 else j
            continue
        elif ch == '/' and text.startswith('/*', i):
            j = text.find('*/', i + 2)
            if j == -1:
                return False
            # A parser "comment" holding a call token may really be a regex
            # literal hiding the invocation; fail closed.
            if _comment_is_suspect(text, i, j + 2, False):
                return False
            i = j + 2
            continue
        elif depth == 1 and body_closed and not ch.isspace():
            # After the function body only the closing paren may follow; a
            # comma operand or any other expression executes at import.
            if ch != ')':
                return False
        if quote is None:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    if not (braces == 0 and body_closed and bool(
                            _only_trailing_noise(text, i + 1))):
                        return False
                    return not _raw_invoked(text, start)
            elif ch == '{':
                braces += 1
            elif ch == '}':
                braces -= 1
                if braces < 0:
                    return False
                if braces == 0 and depth == 1:
                    body_closed = True
        i += 1
    return False


def _is_build_artifact(content):
    """Check if file content has build tool banner comments."""
    first_lines = '\n'.join(content.split('\n', 5)[:5])
    return bool(_BUILD_TOOL_BANNERS.search(first_lines))


def _find_package_json_main(repo_path, rel_dir):
    """Find the 'main' field from the nearest package.json.
    Returns the resolved relative path of the entrypoint, or None."""
    pkg_path = os.path.join(repo_path, rel_dir, 'package.json') if rel_dir else os.path.join(repo_path, 'package.json')
    if not os.path.isfile(pkg_path):
        return None
    try:
        with open(pkg_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        main = data.get('main', 'index.js')
        if not isinstance(main, str):
            return None
        return main
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def scan_js_entrypoint(file_path, rel_path, content):
    """Detect IIFE injection and suspicious patterns in JS entrypoint files."""
    findings = []
    lines = content.split('\n')

    if _is_build_artifact(content):
        return findings

    # Strategy 1: Detect IIFE at end of file
    # Look for IIFE in the last 30% of the file or last 50 lines
    total_lines = len(lines)
    if total_lines == 0:
        return findings

    # Find IIFEs by scanning from the bottom
    tail_start = max(0, total_lines - max(50, int(total_lines * 0.3)))
    tail_content = '\n'.join(lines[tail_start:])

    iife_matches = list(_IIFE_PATTERN.finditer(tail_content))
    # Per-match work is linear in the file, so an adversarial file full of
    # repeated openers would be quadratic. Analyse a bounded number and report
    # the rest as one structural finding (never a silent skip).
    if len(iife_matches) > _MAX_IIFE_MATCHES:
        findings.append(core.Finding(
            scanner=SCANNER_NAME,
            severity="high",
            title="Entrypoint IIFE Injection: Structural Anomaly",
            description=(f"{len(iife_matches)} IIFE openers in one entrypoint tail; only the "
                         f"last {_MAX_IIFE_MATCHES} were analysed to bound scan time."),
            file=rel_path,
            line=tail_start + tail_content[:iife_matches[0].start()].count('\n') + 1,
            snippet="excessive IIFE openers",
            category="entrypoint-iife",
        ))
        iife_matches = iife_matches[-_MAX_IIFE_MATCHES:]
    for match in iife_matches:
        uninvoked_factory = _is_uninvoked_default_export(tail_content, match.start())
        # Determine the line number in the original file
        match_offset = tail_content[:match.start()].count('\n')
        iife_line = tail_start + match_offset + 1

        # Check if the IIFE contains dangerous patterns
        # Extract content from match to end of file for pattern checking
        # A factory is scanned to the end of the file: padding must not
        # push a payload past the window.
        iife_region = (tail_content[match.start():] if uninvoked_factory
                       else tail_content[match.start():match.start() + 10240])
        dangerous_found = []
        for pattern, desc in _IIFE_DANGEROUS_PATTERNS:
            # A NODE_ENV check in an exported-but-never-called factory is
            # normal; every other dangerous primitive still counts there.
            if (uninvoked_factory and desc == "process.env access"
                    and _env_only_gates(iife_region)):
                continue
            if pattern.search(iife_region):
                dangerous_found.append(desc)

        if dangerous_found:
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="critical",
                title="Entrypoint IIFE Injection: Dangerous Code",
                description=(
                    f"IIFE at end of entrypoint file contains dangerous operations: "
                    f"{', '.join(dangerous_found[:3])}. Matches node-ipc supply chain "
                    f"attack pattern (May 2026)"
                ),
                file=rel_path,
                line=iife_line,
                snippet=lines[iife_line - 1].strip()[:120] if iife_line <= total_lines else "",
                category="entrypoint-iife",
            ))
        elif uninvoked_factory:
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="medium",
                title="Entrypoint exported factory (not invoked)",
                description=(
                    "Entrypoint exports a function expression that is never called in "
                    "this file. Normal for plugin factories; reviewed only by the "
                    "dangerous-primitive list, so obfuscated bodies are not ruled out."
                ),
                file=rel_path,
                line=iife_line,
                snippet=lines[iife_line - 1].strip()[:120] if iife_line <= total_lines else "",
                category="entrypoint-iife",
            ))
        else:
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="high",
                title="Entrypoint IIFE Injection: Structural Anomaly",
                description=(
                    "IIFE appended at end of entrypoint file. Legitimate modules "
                    "rarely end with self-executing functions. Review for injected payload."
                ),
                file=rel_path,
                line=iife_line,
                snippet=lines[iife_line - 1].strip()[:120] if iife_line <= total_lines else "",
                category="entrypoint-iife",
            ))

    # Strategy 2: Detect module.exports reassignment at bottom
    # If there are 2+ module.exports assignments, the last one may be injected
    exports_positions = [m.start() for m in _MODULE_EXPORTS_RE.finditer(content)]
    if len(exports_positions) >= 2:
        last_export_offset = exports_positions[-1]
        last_export_line = content[:last_export_offset].count('\n') + 1
        # Only flag if the last export is in the bottom 20% of the file
        if last_export_line > total_lines * 0.8:
            findings.append(core.Finding(
                scanner=SCANNER_NAME,
                severity="high",
                title="Entrypoint: Duplicate module.exports Reassignment",
                description=(
                    "module.exports reassigned at bottom of file after prior exports. "
                    "May indicate injected payload overriding legitimate exports."
                ),
                file=rel_path,
                line=last_export_line,
                snippet=lines[last_export_line - 1].strip()[:120] if last_export_line <= total_lines else "",
                category="entrypoint-iife",
            ))

    # Strategy 3: High-entropy appended content
    # Check last 10 lines for suspicious high-entropy blocks
    tail_lines = lines[max(0, total_lines - 10):]
    for i, line in enumerate(tail_lines):
        stripped = line.strip()
        if len(stripped) < 40:
            continue
        if _HEX_BLOCK.search(stripped) or _BASE64_BLOCK.search(stripped):
            entropy = _shannon_entropy(stripped)
            if entropy > 4.5:  # High entropy threshold
                actual_line = max(0, total_lines - 10) + i + 1
                findings.append(core.Finding(
                    scanner=SCANNER_NAME,
                    severity="medium",
                    title="Entrypoint: High-Entropy Appended Content",
                    description=(
                        f"High-entropy content (Shannon entropy: {entropy:.1f}) at end of "
                        f"entrypoint file. May indicate obfuscated injected payload."
                    ),
                    file=rel_path,
                    line=actual_line,
                    snippet=stripped[:120],
                    category="entrypoint-iife",
                ))
                break  # One finding per file for entropy

    return findings


# ---------------------------------------------------------------------------
# Python import-time execution detection
# ---------------------------------------------------------------------------

# Dangerous module.function combinations at import time
_PYTHON_DANGEROUS_TOPLEVEL_CALLS = {
    # (module, function_name): (severity, description)
    ('os', 'system'): ("high", "os.system() at import time"),
    ('os', 'popen'): ("high", "os.popen() at import time"),
    ('os', 'execv'): ("high", "os.execv() at import time"),
    ('os', 'execve'): ("high", "os.execve() at import time"),
    ('os', 'execvp'): ("high", "os.execvp() at import time"),
    ('subprocess', 'run'): ("critical", "subprocess.run() at import time"),
    ('subprocess', 'call'): ("critical", "subprocess.call() at import time"),
    ('subprocess', 'Popen'): ("critical", "subprocess.Popen() at import time"),
    ('subprocess', 'check_output'): ("critical", "subprocess.check_output() at import time"),
    ('subprocess', 'check_call'): ("critical", "subprocess.check_call() at import time"),
    ('urllib.request', 'urlopen'): ("critical", "urllib.request.urlopen() at import time"),
    ('requests', 'get'): ("critical", "requests.get() at import time (network call on import)"),
    ('requests', 'post'): ("critical", "requests.post() at import time (network call on import)"),
    ('requests', 'put'): ("critical", "requests.put() at import time (network call on import)"),
    ('requests', 'delete'): ("critical", "requests.delete() at import time (network call on import)"),
    ('socket', 'socket'): ("critical", "socket.socket() at import time"),
    ('socket', 'connect'): ("critical", "socket.connect() at import time"),
    ('socket', 'create_connection'): ("critical", "socket.create_connection() at import time"),
    ('http.client', 'HTTPConnection'): ("critical", "http.client.HTTPConnection() at import time"),
    ('http.client', 'HTTPSConnection'): ("critical", "http.client.HTTPSConnection() at import time"),
}

# Bare exec/eval with obfuscated arguments
_EXEC_EVAL_NAMES = {'exec', 'eval'}

# Safe top-level call patterns (os.path.*, os.getcwd, etc.)
_SAFE_OS_ATTRS = {
    'path', 'getcwd', 'getenv', 'environ', 'sep', 'linesep', 'name',
    'curdir', 'pardir', 'extsep', 'altsep', 'pathsep', 'defpath',
}

# Modules that are always safe at top level
_SAFE_MODULES_FOR_CALLS = {
    'os.path', 'pathlib', 'logging', 'warnings', 'typing',
    'collections', 'functools', 'itertools', 'operator',
    'abc', 'enum', 'dataclasses', 'contextlib',
}


def _is_inside_name_main_guard(node, source_lines):
    """Check if a node is inside an 'if __name__ == "__main__"' block."""
    # This is called for top-level If nodes. Check the test condition.
    if not isinstance(node, ast.If):
        return False
    test = node.test
    # Pattern: __name__ == "__main__" or "__main__" == __name__
    if isinstance(test, ast.Compare):
        left = test.left
        if (len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
                and len(test.comparators) == 1):
            comp = test.comparators[0]
            # Check both directions
            if _is_name_main_pair(left, comp) or _is_name_main_pair(comp, left):
                return True
    return False


def _is_name_main_pair(a, b):
    """Check if (a, b) matches (__name__, "__main__") in either form."""
    a_is_name = isinstance(a, ast.Name) and a.id == '__name__'
    # Support both ast.Constant (3.8+) and ast.Str (deprecated)
    b_is_main = (
        (isinstance(b, ast.Constant) and b.value == '__main__')
        or (hasattr(ast, 'Str') and isinstance(b, ast.Str) and b.s == '__main__')
    )
    return a_is_name and b_is_main


def _get_call_info(node):
    """Extract (module, function) tuple from a Call node, or None.

    Handles:
      - module.func()        -> ('module', 'func')
      - module.sub.func()    -> ('module.sub', 'func')
      - bare_func()          -> (None, 'func')
    """
    if not isinstance(node, ast.Call):
        return None

    func = node.func
    if isinstance(func, ast.Attribute):
        # module.func() or module.sub.func()
        parts = []
        current = func.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            module = '.'.join(parts)
            return (module, func.attr)
    elif isinstance(func, ast.Name):
        return (None, func.id)

    return None


def _is_obfuscated_arg(node):
    """Check if an argument to exec/eval looks obfuscated."""
    if not node.args:
        return False
    arg = node.args[0]
    # Call expression as argument (e.g. exec(decode(...)), exec(compile(...)))
    if isinstance(arg, ast.Call):
        return True
    # Binary op (string concatenation)
    if isinstance(arg, ast.BinOp):
        return True
    # JoinedStr (f-string with variables)
    if isinstance(arg, ast.JoinedStr):
        return True
    # Subscript (e.g. exec(d["p"])), IfExp (e.g. exec(a if x else b)),
    # Attribute (e.g. exec(obj.payload))
    if isinstance(arg, (ast.Subscript, ast.IfExp, ast.Attribute)):
        return True
    return False


def scan_python_entrypoint(file_path, rel_path):
    """Detect dangerous top-level calls in Python entrypoint files.

    Only scans __init__.py and setup.py files. Uses Python AST to check
    ast.Module.body for dangerous calls NOT inside FunctionDef or ClassDef.
    """
    findings = []
    basename = os.path.basename(file_path)

    if basename not in ('__init__.py', 'setup.py'):
        return findings

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except OSError:
        return findings

    if not source.strip():
        return findings

    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return findings

    source_lines = source.split('\n')

    def snippet(lineno):
        if lineno and 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1].strip()[:120]
        return ""

    # Walk only top-level statements in ast.Module.body
    for stmt in tree.body:
        # Skip class and function definitions (their bodies are not import-time)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        # Skip if __name__ == "__main__" blocks
        if isinstance(stmt, ast.If) and _is_inside_name_main_guard(stmt, source_lines):
            continue

        # Skip import statements, assignments of constants, type annotations, pass, etc.
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass,
                             ast.AnnAssign)):
            continue

        # For Assign and AugAssign, check if the value is a dangerous call
        # but skip simple constant assignments
        if isinstance(stmt, ast.Assign):
            if isinstance(stmt.value, (ast.Constant, ast.List, ast.Tuple,
                                       ast.Dict, ast.Set, ast.Name)):
                continue
            # Check if the value is a safe call (like os.path.dirname())
            if isinstance(stmt.value, ast.Call):
                call_info = _get_call_info(stmt.value)
                if call_info:
                    mod, func = call_info
                    if mod in _SAFE_MODULES_FOR_CALLS:
                        continue
                    if mod == 'os' and func in _SAFE_OS_ATTRS:
                        continue
                    # os.path.X is safe
                    if mod and mod.startswith('os.path'):
                        continue

        # Walk all Call nodes within this top-level statement
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue

            lineno = getattr(node, 'lineno', 0)
            call_info = _get_call_info(node)

            if call_info is None:
                continue

            mod, func = call_info

            # Check for dangerous module.function calls
            if mod is not None:
                key = (mod, func)
                if key in _PYTHON_DANGEROUS_TOPLEVEL_CALLS:
                    severity, desc = _PYTHON_DANGEROUS_TOPLEVEL_CALLS[key]
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity=severity,
                        title=f"Entrypoint Import-Time Execution: {desc}",
                        description=(
                            f"Top-level {mod}.{func}() call in {basename} executes on "
                            f"import. Matches durabletask supply chain attack pattern "
                            f"(May 2026). This code runs automatically when the "
                            f"package is imported."
                        ),
                        file=rel_path,
                        line=lineno,
                        snippet=snippet(lineno),
                        category="entrypoint-import-exec",
                    ))
                    continue

                # Safe os.path calls etc. - skip
                if mod in _SAFE_MODULES_FOR_CALLS or mod.startswith('os.path'):
                    continue
                if mod == 'os' and func in _SAFE_OS_ATTRS:
                    continue

            # Check for bare exec/eval at top level
            if mod is None and func in _EXEC_EVAL_NAMES:
                if _is_obfuscated_arg(node):
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity="critical",
                        title=f"Entrypoint Import-Time Execution: {func}() with obfuscated argument",
                        description=(
                            f"Top-level {func}() with computed argument in {basename}. "
                            f"Executes obfuscated code at import time. Classic supply "
                            f"chain payload delivery."
                        ),
                        file=rel_path,
                        line=lineno,
                        snippet=snippet(lineno),
                        category="entrypoint-import-exec",
                    ))
                else:
                    findings.append(core.Finding(
                        scanner=SCANNER_NAME,
                        severity="high",
                        title=f"Entrypoint Import-Time Execution: {func}() at top level",
                        description=(
                            f"Top-level {func}() in {basename}. Executes arbitrary "
                            f"code at import time."
                        ),
                        file=rel_path,
                        line=lineno,
                        snippet=snippet(lineno),
                        category="entrypoint-import-exec",
                    ))

    return findings


# ---------------------------------------------------------------------------
# Main scanner entry point
# ---------------------------------------------------------------------------

def scan_file(file_path, rel_path):
    """Scan a single file for entrypoint payload injection.
    Returns list[core.Finding]."""
    findings = []
    basename = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    # Python entrypoint files
    if basename in ('__init__.py', 'setup.py'):
        findings.extend(scan_python_entrypoint(file_path, rel_path))

    # JavaScript/CJS entrypoint files
    # We scan all .js/.cjs files that could be entrypoints
    # The main heuristic: scan package.json main field targets + any index.js/index.cjs
    if ext in CJS_EXTENSIONS:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except OSError:
            return findings

        if content.strip():
            findings.extend(scan_js_entrypoint(file_path, rel_path, content))

    return findings


def main():
    args = core.parse_common_args(sys.argv, "Entrypoint Payload Scanner")
    repo_path = args.repo_path

    core.emit_status(args.format, f"[*] Scanning entrypoint files in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    all_findings = []

    # Collect package.json main fields to identify JS entrypoints
    entrypoint_files = set()
    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        if os.path.basename(file_path) == 'package.json':
            pkg_dir = os.path.dirname(rel_path)
            main_file = _find_package_json_main(repo_path, pkg_dir)
            if main_file:
                entrypoint_rel = os.path.normpath(os.path.join(pkg_dir, main_file)) if pkg_dir else main_file
                entrypoint_files.add(entrypoint_rel)

    for file_path, rel_path in core.walk_repo(repo_path, ignore_patterns, skip_binary=True):
        basename = os.path.basename(file_path)
        ext = os.path.splitext(file_path)[1].lower()

        # Always scan Python entrypoints
        if basename in ('__init__.py', 'setup.py'):
            all_findings.extend(scan_python_entrypoint(file_path, rel_path))

        # Scan JS files that are package.json entrypoints or index files
        elif ext in CJS_EXTENSIONS:
            is_entrypoint = (
                rel_path in entrypoint_files
                or os.path.normpath(rel_path) in entrypoint_files
                or basename in ('index.js', 'index.cjs', 'index.mjs')
            )
            if is_entrypoint:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except OSError:
                    continue
                if content.strip():
                    all_findings.extend(scan_js_entrypoint(file_path, rel_path, content))

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
