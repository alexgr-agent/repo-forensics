#!/usr/bin/env python3
"""
pre_scan.py - pre-execution hook handler for repo-forensics v2.
Lightweight gate that blocks known-malicious packages and pipe-to-shell
patterns BEFORE the command runs.

Runs as a Claude Code / Codex / OpenClaw **PreToolUse** hook and as a Cursor
**beforeShellExecution** hook (`--adapter cursor`). Reads JSON from stdin,
outputs JSON to stdout. Full scans run post-execution in auto_scan.py.

Design constraints (all critical for safety):
  - Inspection runs in this process. Untrusted command text is never executed.
    Structural work limits never depend on wall time or machine load.
  - MUST NOT block commands when IOC database is unavailable (graceful
    degradation — approve on error, never silently block legitimate work)
  - MUST output valid JSON to stdout in all code paths (empty {} = approve
    on the Claude shape, {"permission": ...} on the Cursor shape)
  - MUST exit 0 for approve/ask, exit 2 for block

Adapters (PRD v3 R2/G3): envelope normalisation and verdict rendering live in
hook_adapter.py so both wires run the SAME detection code. hook_adapter is a
leaf (stdlib only, no repo imports); importing it does not weaken the
"pre_scan stays standalone" rule, which is about never pulling in auto_scan or
the scanner fan-out.

Verdict precedence on the blocking path (PRD v3 R8/R11 — see
hook_adapter.PRECEDENCE_DOC):

    REPO_FORENSICS_PRE_SCAN=unsafe-off   allow everything, loudly
  > install-manifest tamper              deny  (NOT user-suppressible)
  > envelope drift on a failClosed wire  deny  (NOT user-suppressible)
  > REPO_FORENSICS_PRE_SCAN=0            allow, loudly
  > detection verdict                    deny / ask / allow

The two integrity states outrank the ordinary kill switch on purpose: the
switch is read from the session environment, so an earlier command in the same
session can plant it. If it could also mask a deleted scanner or a spoofed
envelope, one planted variable would buy an attacker the whole gate.

Created by Alex Greenshpun
"""

import json
import os
import re
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

import hook_adapter  # noqa: E402  (leaf module, stdlib-only)

# --- Pattern Detection ---
# NOTE: These patterns are intentionally duplicated from auto_scan.py.
# pre_scan.py MUST remain standalone (no imports from auto_scan, no subprocess)
# to guarantee <10ms latency and zero recursion risk. If you update patterns
# here, update auto_scan.py too (and vice versa).

class _PmPattern:
    """Linear flag-prefix matching, including optional flag values.

    Cache valid suffixes once instead of retrying the same flag chain at every
    tool word. Return a regex match so package extraction keeps its contract.
    """
    def __init__(self, tool, subcommands):
        self.tool = re.compile(re.escape(tool) + r'\s+')
        self.subcommand = re.compile('(?:' + subcommands + r')\s+(.+)')
        self.head = re.compile('(?:' + subcommands + r')\s+(?=[^\n])')

    def search(self, command):
        candidates = list(self.tool.finditer(command))
        if not candidates:
            return None
        words = list(re.finditer(r'\S+', command))
        starts = {word.start(): i for i, word in enumerate(words)}
        valid = [None] * (len(words) + 2)
        reserved = re.compile(r'(?:install|i|add|update|sync|pip|tool|remove|run)\b')
        for i in range(len(words) - 1, -1, -1):
            if not i % 16:
                _ps_check_work()
            word = words[i][0]
            if re.fullmatch(r'-{1,2}[^-\s]\S*', word) and words[i].end() < len(command):
                optional = i + 1 < len(words) and not words[i + 1][0].startswith('-') and not reserved.match(words[i + 1][0])
                valid[i] = valid[i + 2] if optional and valid[i + 2] is not None else valid[i + 1]
            elif re.match(r'(?:install|i|add|update|pip|tool)\b', word):
                match = self.head.match(command, words[i].start())
                if match:
                    valid[i] = words[i].start()
        for candidate in candidates:
            i = starts.get(candidate.end())
            if i is not None and valid[i] is not None:
                return self.subcommand.match(command, valid[i])
        return None


INSTALL_PATTERNS = [
    # uv/pnpm must precede pip/npm: the patterns are unanchored, so
    # 'uv pip install x' / 'pnpm install x' substring-match the pip/npm entries.
    # _PmPattern covers flags between the tool and subcommand (monorepo forms).
    (_PmPattern('uv', r'add|pip\s+install|tool\s+install'), 'uv_install'),
    (re.compile(r'pip3?\s+install\s+(.+)'), 'pip_install'),
    (_PmPattern('pnpm', r'install|i|add|update'), 'pnpm_install'),
    (_PmPattern('bun', r'install|i|add|update'), 'bun_install'),
    (re.compile(r'npm\s+(?:install|i)\s+(.+)'), 'npm_install'),
    (re.compile(r'npm\s+update\s+(.+)'), 'npm_install'),
    (re.compile(r'yarn\s+add\s+(.+)'), 'yarn_add'),
    (re.compile(r'gem\s+(?:install|update)\s+(.+)'), 'gem_install'),
    (re.compile(r'cargo\s+install\s+(.+)'), 'cargo_install'),
    (re.compile(r'go\s+(?:get|install)\s+(.+)'), 'go_install'),
    (re.compile(r'brew\s+(?:install|upgrade)\s+(.+)'), 'brew_install'),
    (re.compile(r'openclaw\s+(?:skills|plugins)\s+(?:install|update)\s+(.+)'), 'openclaw_install'),
    (re.compile(r'clawhub\s+(?:install|publish)\s+(.+)'), 'openclaw_install'),
]

_DOWNLOADERS = r'(?:curl|wget|aria2c|http|Invoke-WebRequest)'
_SHELLS = r'(?:sudo\s+)?(?:/[\w/.-]*/)?(?:bash|zsh|dash|ksh|csh|tcsh|fish|pwsh|sh)(?!\w)'
_BASE64_PIPE = r'base64\s+(?:-d|--decode)\s*\|'

_PIPE_EVENTS = re.compile(_DOWNLOADERS + r'\s+|[|>]', re.I)
_PIPE_SINK = re.compile(r'\|\s*(?:' + _BASE64_PIPE + r'\s*)?(?:' + _SHELLS + r'|iex)', re.I)
_BASE64_SINK = re.compile(_BASE64_PIPE + r'\s*(?:' + _SHELLS + r'|iex)', re.I)
_TEMP_SINK = re.compile(r'>\s*/tmp/[^\s;]+\s*(?:;|&&?)\s*' + _SHELLS + r'\s+/tmp/', re.I)


def has_pipe_to_shell(command):
    """Preserve legacy signals without retrying a suffix at every fetch word."""
    if _BASE64_SINK.search(command):
        return True
    fetched_pipe = fetched_file = False
    for index, event in enumerate(_PIPE_EVENTS.finditer(command)):
        if not index % 16:
            _ps_check_work()
        if event[0] == '|':
            if fetched_pipe and _PIPE_SINK.match(command, event.start()):
                return True
            fetched_pipe = False
        elif event[0] == '>':
            if fetched_file and _TEMP_SINK.match(command, event.start()):
                return True
            fetched_file = False
        else:
            fetched_pipe = fetched_file = True
    return False

# Strip ONLY the flag token itself, never a following "value" — otherwise a
# boolean flag swallows the next package (`npm install foo --save-exact keyv@6.0.0`
# hid keyv). A real value-flag's argument (a URL, a path) is left as a token, but
# it harmlessly matches no IOC. Every non-flag token must reach the IOC checks.
INSTALL_FLAGS = re.compile(r'\s+--?[a-zA-Z][\w-]*')


def parse_hook_input():
    """Read and parse PreToolUse JSON from stdin."""
    try:
        raw = sys.stdin.read(1_048_576)  # 1MB max
        if not raw.strip():
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, IOError):
        return None


def extract_command(data):
    """Extract the bash command from hook payload."""
    if not data:
        return None
    if data.get('tool_name', '') != 'Bash':
        return None
    tool_input = data.get('tool_input', {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            return None
    return tool_input.get('command', '')


# --- Inert quote carriers ---------------------------------------------------
# A pipe-to-shell pattern inside a quoted argument to a command that never
# executes its arguments is someone WRITING ABOUT the attack, not performing
# it — a `git commit -m` whose message warns against downloader-to-shell
# pipelines, a `grep` searching the docs for them, an `echo` telling the reader
# not to. Blocking those is the false positive that gets a blocking hook
# uninstalled, and it fires on this repo's own commit messages, which discuss
# pipe-to-shell constantly. (These examples are deliberately paraphrased rather
# than written out: pre_scan.py and auto_scan.py are the blocking gate and stay
# OUT of .forensicsignore, so a literal payload here would be a finding the
# scanner reports against itself — see tests/test_cursor_wiring.py.)
#
# This is the command-string analogue of the evidence model forensics_core
# already applies to files (a README that DESCRIBES an attack is not the
# attack). The suppression is deliberately narrow, because the obvious wide
# version — "ignore anything inside quotes" — is a bypass, not a fix: a
# downloader-to-shell pipeline handed to `sh -c` as a quoted argument is both
# quoted AND executed. So two conditions must BOTH hold: the command starts
# with a known inert carrier, and the residue left after deleting every quoted
# span contains no shell execution of its own. An `echo` whose quoted argument
# is itself piped onward to a shell keeps that residual pipe and still blocks.
# Kept identical in auto_scan.py — update both.
# Only commands whose job is to RECORD or SEARCH FOR text, never to produce a
# stream someone would plausibly pipe onward. `cat`, `jq` and friends are
# deliberately absent: their output being piped to a shell is a normal thing to
# do, so they do not belong on a list whose whole premise is "this argument is
# inert prose". (The residual-exec check below would catch a piped `cat` too,
# but a suppression list should not lean on a second layer to stay safe.)
_INERT_CARRIERS = re.compile(
    r'^\s*(?:'
    r'echo|printf|grep|egrep|fgrep|rg|ag|ack'
    r'|git\s+(?:commit|tag|notes|stash\s+save|config)'
    r'|gh\s+(?:issue|pr|release)\s+[a-z-]+'
    r')\b',
    re.IGNORECASE,
)

# Quoted spans: single- or double-quoted, non-greedy, no cross-line matching.
_QUOTED_SPAN = re.compile(r"'[^']*'|\"[^\"]*\"")

# Residual shell execution after quoted spans are removed. Any of these means
# the command really does hand something to a shell, so no suppression.
_RESIDUAL_EXEC = re.compile(
    r'\|\s*(?:' + _SHELLS + r'|iex)'
    r'|(?:^|[\s;&|(])(?:eval|exec|source)\b'
    r'|\B-c(?:\s|$)'
    r'|(?:^|[\s;&|(])' + _SHELLS + r'\s+-c',
    re.IGNORECASE,
)


def is_inert_quote_carrier(command):
    """True when every pipe-to-shell signal in *command* sits inside a quoted
    argument to a command that does not execute its arguments."""
    if not command or not _INERT_CARRIERS.match(command):
        return False
    residue = _QUOTED_SPAN.sub(' ', command)
    if _RESIDUAL_EXEC.search(residue):
        return False
    # The signal must be gone once the quotes are removed. If it survives, it
    # was never inside a quoted argument in the first place — an inert carrier
    # followed by `;` and then a real downloader-to-shell pipeline.
    return not has_pipe_to_shell(residue)


# PowerShell download/execution gate. Deliberately duplicated in auto_scan:
# pre_scan must not import the post-hook (scanner fan-out / recursion risk).
_PS_FETCH = frozenset(('irm', 'iwr', 'curl', 'wget', 'fetch', 'sbt', 'invoke-restmethod',
                       'invoke-webrequest', 'start-bitstransfer', 'curl.exe', 'wget.exe', 'aria2c', 'xh', 'http'))
_PS_HINT = re.compile(r'(?:\b(?:irm|iwr|curl|wget|aria2c|xh|http|fetch|sbt|invoke-restmethod|invoke-webrequest|start-bitstransfer|certutil|bitsadmin|mshta|regsvr32|rundll32|powershell(?:_ise)?|pwsh(?:7|-preview)?)\b|downloadstring|downloadfile|downloaddata|getstringasync|webrequest|openread|(?<!\w)-(?:enc\w*|e|ec)\b)', re.IGNORECASE)
# A short flag alone does not name a PowerShell command. Alias/host spelling
# syntax still needs normalization before it can be ruled out.
_PS_CONTENT_HINT = re.compile(_PS_HINT.pattern.replace(r'|(?<!\w)-(?:enc\w*|e|ec)\b', ''), re.IGNORECASE)
_PS_HOST_SPELLING = re.compile(r'[$%*?\[=]')

_PS_EXEC = frozenset(('iex', 'invoke-expression', 'invoke-expr', 'invoke-command', 'import-module', 'ipmo', 'icm', 'add-type'))
_PS_SHELL = frozenset(('sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'bash.exe', 'csh', 'tcsh', 'fish'))
_PS_HOST = frozenset(('powershell', 'powershell.exe', 'powershell_ise', 'pwsh', 'pwsh.exe', 'pwsh-preview', 'pwsh7', 'pwsh.dll'))
_PS_CODE_HOST = _PS_HOST | _PS_SHELL
_PS_STDIN_HOST = frozenset(('python', 'python3', 'perl', 'ruby', 'node'))
_PS_COMMAND_NAMES = _PS_CODE_HOST | _PS_EXEC
_PS_SINK_NAMES = _PS_COMMAND_NAMES | _PS_STDIN_HOST | frozenset(('cmd', 'cmd.exe', 'eval', 'source', '.'))
_PS_FILE_SINK_NAMES = _PS_COMMAND_NAMES | _PS_STDIN_HOST | frozenset(('.', 'source', 'wscript', 'cscript'))
_PS_SPACE = re.compile(r'\s+')
_PS_BRACED_LITERAL = re.compile(r'\$\{[A-Za-z_][\w:]*\}')
_PS_ENCODED = frozenset(('e', 'ec', 'en', 'enc', 'enco', 'encod', 'encode',
                         'encoded', 'encodedc', 'encodedco', 'encodedcom',
                         'encodedcomm', 'encodedcomma', 'encodedcomman',
                         'encodedcommand'))


class _PsInspectionLimit(Exception):
    """Inspection stopped before it could establish an execution verdict."""

    def __str__(self):
        message = super().__str__()
        return message if 'split the command' in message.lower() else message + '; split the command'


from contextvars import ContextVar
import signal
import threading
import time
_PS_WORK_START = ContextVar('inspection_cpu_start', default=None)
# Process-CPU seconds one hook invocation may spend inspecting a command. A
# hook process counts from interpreter start, so the whole invocation stays
# under 2 CPU seconds including the launcher.
_PS_WORK_BUDGET = 1.5
_PS_HARD_STOP = {'armed': False, 'expired': False}


def _ps_check_work():
    started = _PS_WORK_START.get()
    if started is not None and (_PS_HARD_STOP['expired'] or time.process_time() - started > _PS_WORK_BUDGET):
        raise _PsInspectionLimit('inspection work budget exceeded')


_PS_TICKS = [0]


def _ps_tick():
    """Cheap budget check for hot helpers called from nested token loops."""
    _PS_TICKS[0] += 1
    if not _PS_TICKS[0] & 1023:
        _ps_check_work()


def _ps_on_budget_signal(signum, frame):
    _PS_HARD_STOP['expired'] = True
    # Never raise inside the guard itself: it is entering or leaving the
    # timer, and its own final check turns the expired flag into a refusal.
    if _PS_HARD_STOP['armed'] and frame is not None and frame.f_code not in _PS_HARD_STOP_QUIET:
        raise _PsInspectionLimit('inspection work budget exceeded')


def _ps_arm_hard_stop():
    """Make the work budget a hard stop, not only a check between steps.

    On POSIX, in the main thread, a process-CPU timer interrupts whatever
    Python code is running once the budget is spent, and keeps re-firing every
    20 ms so a broad except cannot swallow it. Elsewhere (Windows, worker
    threads) the cooperative checks remain the only bound.
    """
    if _PS_HARD_STOP['armed'] or not hasattr(signal, 'setitimer'):
        return None
    if threading.current_thread() is not threading.main_thread():
        return None
    started = _PS_WORK_START.get()
    remaining = _PS_WORK_BUDGET - (time.process_time() - started if started is not None else 0.0)
    try:
        previous = signal.signal(signal.SIGPROF, _ps_on_budget_signal)
    except (ValueError, OSError):
        return None
    _PS_HARD_STOP.update(armed=True, expired=False)
    try:
        prior_timer = signal.setitimer(signal.ITIMER_PROF, max(remaining, 0.001), 0.02)
    except (ValueError, OSError, AttributeError):
        _PS_HARD_STOP.update(armed=False)
        signal.signal(signal.SIGPROF, previous)
        return None
    return previous, prior_timer


def _ps_disarm_hard_stop(state):
    if state is None:
        return
    signal.setitimer(signal.ITIMER_PROF, 0)
    _PS_HARD_STOP.update(armed=False, expired=False)
    signal.signal(signal.SIGPROF, state[0])
    if state[1][0] > 0:
        signal.setitimer(signal.ITIMER_PROF, *state[1])


def _ps_guard_inspection(operation, *args, on_error, hard_stop=True):
    """Unexpected inspection failures cannot approve work or leak tracebacks."""
    token = _PS_WORK_START.set(time.process_time()) if _PS_WORK_START.get() is None else None
    armed = None
    try:
        armed = _ps_arm_hard_stop() if hard_stop else None
        result = operation(*args)
        _ps_check_work()
        return result
    except _PsInspectionLimit as limit:
        return on_error[0], '[repo-forensics] BLOCKED: ' + str(limit)
    except Exception:
        return on_error
    finally:
        _ps_disarm_hard_stop(armed)
        if token is not None:
            _PS_WORK_START.reset(token)


_PS_HARD_STOP_QUIET = frozenset((_ps_guard_inspection.__code__, _ps_disarm_hard_stop.__code__, _ps_arm_hard_stop.__code__))


class _PsTokens(list):
    """Cache statement boundaries so command-position queries do not rescan."""
    def __getitem__(self, key):
        value = super().__getitem__(key)
        return _PsTokens(value) if isinstance(key, slice) else value

    def statement_start(self, index, start):
        if not hasattr(self, '_starts'):
            self._starts = []
            begin = 0
            for at, (_, value) in enumerate(self):
                self._starts.append(begin)
                if value in (';', '|', '(', '{', '&'):
                    begin = at + 1
        return max(start, self._starts[index])


def _ps_shell_hosts(command):
    """Fold shell quoting/escapes only when a word names a known host."""
    command = re.sub(r'\$\{IFS\}|\$IFS\b', ' ', command)
    command = re.sub(r'\b(cmd(?:\.exe)?\s+/[ck]\s+)"("[^\n]+)"', r'\1\2', command, flags=re.I)
    if re.search(r'\bcmd(?:\.exe)?\s+/[ck]\b', command, re.I):
        command = re.sub(r'\b[\w^]+\b', lambda m: m[0].replace('^', '') if m[0].replace('^', '').lower() in _PS_HOST else m[0], command)
    def literal_name(text):
        parts = _ps_tokens(text, dialect='powershell')
        if len(parts) >= 3 and parts[0][0] in ('string', 'double') and parts[1][1] == '-f':
            template = parts[0][1]
            values = [value for kind, value in parts[2:] if kind in ('string', 'double')]
            if len(template) <= 128 and len(values) <= 64 and all(len(value) <= 128 for value in values) and re.fullmatch(r'(?:[^{}]|\{\d{1,2}\})+', template):
                name = re.sub(r'\{(\d+)\}', lambda m: values[int(m[1])] if int(m[1]) < len(values) else m[0], template).lower()
                return name if name in _PS_COMMAND_NAMES else ''
        if not parts or any(kind not in ('string', 'double') if i % 2 == 0 else value != '+' for i, (kind, value) in enumerate(parts)):
            return ''
        name = ''.join(value for kind, value in parts[::2]).lower()
        return name if name in _PS_COMMAND_NAMES else ''
    def fold_literal(match):
        name = literal_name(match[match.lastindex])
        prefix = match[1] if match.lastindex == 2 else '& '
        return prefix + name if name else match[0]
    command = re.sub(r'&\s*\(([^()\r\n]*)\)', fold_literal, command)
    literal = r'''(?:'[^'\r\n]*'|"[^"\r\n]*")'''
    command = re.sub(r'(\$[\w:]+\s*=\s*)(' + literal + r'(?:\s*\+\s*' + literal + r')+)', fold_literal, command)
    command = re.sub(r'\$\((?:which|command\s+-v)\s+(pwsh|powershell)(?:\.exe)?\s*\)|`(?:which|command\s+-v)\s+(pwsh|powershell)(?:\.exe)?\s*`', lambda m: m[1] or m[2], command, flags=re.I)
    output, i = [], 0
    while i < len(command):
        if not i % 16:
            _ps_check_work()
        if command[i].isspace():
            span = _PS_SPACE.match(command, i)
            output.append(span[0])
            i = span.end()
            continue
        if command[i] in '|;(){}&,=':
            output.append(command[i])
            i += 1
            continue
        start, value = i, []
        while i < len(command) and not command[i].isspace() and command[i] not in '|;(){}&,=':
            c = command[i]
            if c in "'\"":
                quote = c
                i += 1
                end = command.find(quote, i)
                if end >= 0 and (quote == "'" or '\\' not in command[i:end]):
                    value.append(command[i:end])
                    i = end + 1
                    continue
                while i < len(command) and command[i] != quote:
                    if quote == '"' and command[i] == '\\' and i + 1 < len(command) and command[i + 1] in '$`"\\\n':
                        i += 1
                    value.append(command[i])
                    i += 1
                if i < len(command):
                    i += 1
            elif c == '\\' and i + 1 < len(command):
                value.append(command[i + 1])
                i += 2
            else:
                value.append(c)
                i += 1
        word = ''.join(value).lower()
        if word.startswith('$') and command[start:start + 2] == "$'":
            word = word[1:]
        name = word.replace('\\', '/').rsplit('/', 1)[-1]
        output.append(name if name in _PS_HOST else command[start:i])
    return ''.join(output)


# Options that consume a separate argument belong to their launcher, not to
# the executable it launches. Boolean flags never consume the next command.
_PS_LAUNCH_OPTIONS = {
    'sudo': ('-u','-g','-h','-p','-c','-r','-t','--user','--group'),
    'doas': ('-u','-C'), 'env': ('-u','-c','--unset','--chdir'),
    'timeout': ('-s','-k','--signal','--kill-after'),
    'exec': ('-a',), 'xargs': ('-n','-s','-l','-L','-i','-I','-P','--max-args','--max-procs','--replace'),
    'nice': ('-n',), 'ionice': ('-c','-n','-p','-P','-u'),
    'stdbuf': ('-i','-o','-e'), 'taskset': ('-c','--cpu-list'),
    'flock': ('-w','-E','--timeout','--conflict-exit-code'),
    'watch': ('-n','--interval'), 'chrt': ('-p',),
    'nsenter': ('-t','--target','--root','--wd'),
    'wsl': ('-d','--distribution','-u','--user','--cd'),
    'wsl.exe': ('-d','--distribution','-u','--user','--cd'),
}
_PS_LAUNCHERS = frozenset(_PS_LAUNCH_OPTIONS) | frozenset((
    'setsid','unbuffer','chroot','nohup','time','command','!', 'then','do',
    'else','if','start','cmd','cmd.exe','dotnet','wsl','wsl.exe'))


def _ps_position(tokens, index, start=0):
    """Walk launcher argv roles; stop at a real command's arguments."""
    _ps_tick()
    if index == start or tokens[index - 1][1] in ('(', '|', ';', '{', '&', '.', '=', '-command', '-c', '/c', '/command', 'in'):
        return True
    if not isinstance(tokens, _PsTokens):
        tokens = _PsTokens(tokens)
    begin = tokens.statement_start(index, start)
    if not hasattr(tokens, '_launch_positions'):
        tokens._launch_positions = {}
    state = tokens._launch_positions.setdefault(begin, {'cursor':begin, 'positions':{begin}, 'seen':0, 'stopped':False})
    cursor = state['cursor']
    while cursor < index and not state['stopped']:
        state['seen'] += 1
        if not state['seen'] % 256:
            _ps_check_work()
        if state['seen'] > 4096:
            raise _PsInspectionLimit('executable wrapper nesting limit exceeded')
        if cursor + 2 < len(tokens) and tokens[cursor + 1] == ('symbol', '=') and re.fullmatch(r'\$?[a-z_][\w:]*', tokens[cursor][1]):
            cursor += 3
            state['positions'].add(cursor)
            continue
        name = _ps_name(tokens, cursor)
        if tokens[cursor][1] == '--':
            cursor += 1
            state['positions'].add(cursor)
            continue
        if name not in _PS_LAUNCHERS:
            state['stopped'] = True
            break
        cursor += 1
        if name == 'start' and cursor < len(tokens) and tokens[cursor][1] == '':
            cursor += 1
        consumed_cpu = False
        while cursor < len(tokens) and (tokens[cursor][1].startswith('-') or (name in ('cmd','cmd.exe') and tokens[cursor][1] in ('/c','/k'))):
            flag = tokens[cursor][1]
            cursor += 1
            if flag == '--':
                break
            if cursor < len(tokens) and tokens[cursor][1] == '=':
                cursor += 2
            elif flag in _PS_LAUNCH_OPTIONS.get(name, ()) and cursor < len(tokens):
                cursor += 1
                consumed_cpu = consumed_cpu or name == 'taskset'
            if name == 'xargs' and flag.lower().startswith('-i') and cursor < len(tokens) and tokens[cursor][1] == '{':
                cursor += 2
        if name in ('timeout','chroot','flock','chrt') or (name == 'taskset' and not consumed_cpu):
            cursor += 1
        state['positions'].add(cursor)
    state['cursor'] = cursor
    return index in state['positions']


def _ps_command_flag(value):
    _ps_tick()
    flag = value.lstrip('-/').split(':', 1)[0].lower()
    return value.startswith(('-', '/')) and (flag == 'c' or (len(flag) >= 2 and 'command'.startswith(flag)) or (flag == 'cwa' or (len(flag) >= 7 and 'commandwithargs'.startswith(flag))))


def _ps_code_flag(value, host):
    _ps_tick()
    if host in _PS_SHELL:
        return bool(re.fullmatch(r'-[a-zA-Z]*c[a-zA-Z]*', value))
    return _ps_command_flag(value)


def _ps_tokens(command, dialect='shell'):
    """A bounded lexical view, not a PowerShell evaluator. Never runs code.

    Keep literal strings separate from code; command/Invoke-Expression strings
    are inspected only at their execution sites. Remove PowerShell backtick
    escapes from names and join escaped line continuations. Comments are inert.
    """
    tokens = _PsTokens()
    nesting = fragments = 0
    last_end = -1
    parts = []
    def finish_word():
        if parts:
            tokens[-1] = tokens[-1][0], ''.join(parts)
            parts.clear()
    def append_word(kind, value, start, end):
        nonlocal last_end
        if dialect == 'shell' and last_end == start and tokens and tokens[-1][0] in ('word', 'string', 'double'):
            previous_kind = tokens[-1][0]
            if previous_kind == 'word':
                parts[-1] = re.sub(r'\$([A-Za-z_]\w*)$', r'${\1}', parts[-1])
            kind = 'word' if 'word' in (kind, previous_kind) else 'double' if 'double' in (kind, previous_kind) else 'string'
            parts.append(value)
            tokens[-1] = kind, ''
        else:
            finish_word()
            tokens.append((kind, value))
            parts.append(value)
        last_end = end
    i, n = 0, len(command)
    while i < n:
        if len(tokens) > 2097152:
            raise _PsInspectionLimit('executable fragment count limit exceeded')
        c = command[i]
        if not c.isspace():
            fragments += 1
            if not fragments % 16:
                _ps_check_work()
            if fragments > 2097152:
                raise _PsInspectionLimit('executable fragment count limit exceeded')
        token_start = i
        if dialect == 'shell' and command[i:i + 2] == "$'":
            i += 1
            c = "'"
        if c.isspace():
            finish_word()
            last_end = -1
            start = i
            i = _PS_SPACE.match(command, i).end()
            if '\n' in command[start:i] and tokens and tokens[-1] != ('symbol', '|') and command[i:i + 1] != '|':
                tokens.append(('symbol', ';'))
        elif command.startswith('<#', i):
            finish_word()
            end = command.find('#>', i + 2)
            i = n if end < 0 else end + 2
        elif c == '#':
            finish_word()
            end = command.find('\n', i)
            if end >= 0 and tokens and tokens[-1] != ('symbol', '|'):
                tokens.append(('symbol', ';'))
            i = n if end < 0 else end + 1
        elif dialect == 'shell' and c == '`' and command.find('`', i + 1) >= 0:
            finish_word()
            last_end = -1
            end = command.find('`', i + 1)
            if end == i + 1:
                i = end + 1
                continue
            tokens.append(('symbol', '('))
            tokens.extend(_ps_tokens(command[i + 1:end], dialect))
            tokens.append(('symbol', ')'))
            i = end + 1
        elif c in "'\"":
            quote, value = c, []
            i += 1
            end = command.find(quote, i)
            if end >= 0 and command[end + 1:end + 2] not in ("'", '"') and command[end + 1:end + 3] != "\\'" and (quote == "'" or ('\\' not in command[i:end] and '`' not in command[i:end])):
                append_word('double' if quote == '"' else 'string', command[i:end], token_start, end + 1)
                i = end + 1
                continue
            while i < n:
                if command[i] == quote:
                    if dialect != 'shell' and i + 1 < n and command[i + 1] == quote:
                        value.append(quote)
                        i += 2
                        continue
                    i += 1
                    if dialect == 'shell' and command[i:i + 3] == "\\''":
                        value.append("'")
                        i += 3
                        continue
                    if dialect == 'shell' and i < n and command[i] in "'\"":
                        quote = command[i]
                        i += 1
                        continue
                    break
                if dialect == 'shell' and quote == '"' and command[i] == '\\' and i + 1 < n and command[i + 1] in ('"', '\\', '$', '`', '\n'):
                    # Shell -c strings escape nested quotes with backslashes.
                    value.append(command[i + 1])
                    i += 2
                    continue
                if quote == '"' and command[i] == '`' and i + 1 < n:
                    # Retain the escape marker so an escaped dollar is inert.
                    value.append('`')
                    i += 1
                value.append(command[i])
                i += 1
            append_word('double' if quote == '"' else 'string', ''.join(value), token_start, i)
        elif c in '<>':
            fd = ''
            adjacent = last_end == i
            finish_word()
            if adjacent and tokens and tokens[-1][0] == 'word' and tokens[-1][1].isdigit():
                fd = tokens.pop()[1]
            end = i + 1
            while end < n and command[end] == c and end - i < 3:
                end += 1
            operator = command[i:end]
            if fd not in ('', '0' if c == '<' else '1'):
                operator = fd + operator
            tokens.append(('word', operator))
            last_end = -1
            i = end
        elif command.startswith('&&', i):
            finish_word()
            last_end = -1
            tokens.append(('symbol', ';'))
            i += 2
        elif c in '|;(){}&,=':
            finish_word()
            last_end = -1
            if c in '({':
                nesting += 1
                if nesting > 4096:
                    raise _PsInspectionLimit('lexical nesting limit exceeded')
            elif c in ')}':
                nesting = max(0, nesting - 1)
            tokens.append(('symbol', c))
            i += 1
        else:
            value = []
            while i < n and not command[i].isspace() and command[i] not in "'\"|;(){}&,=#<>":
                variable = _PS_BRACED_LITERAL.match(command, i) if command.startswith('${', i) else None
                if variable:
                    value.append(variable[0])
                    i = variable.end()
                    continue
                if command[i] == '`' and i + 1 < n:
                    i += 1
                    if command[i] in '\r\n':
                        if command[i] == '\r' and i + 1 < n and command[i + 1] == '\n':
                            i += 1
                        i += 1
                        continue
                value.append(command[i])
                i += 1
            word = ''.join(value)
            append_word('word', word if word.startswith('-') else word.lower(), token_start, i)
    finish_word()
    return tokens


def _ps_glob_units(pattern, longest):
    """Parse a wildcard word in one pass; None when it cannot match a short name.

    A command word is attacker text, so it is never handed to fnmatch as a
    pattern (fnmatch rescans for ']' after every '[', which is quadratic). Each
    '[' looks for its closing ']' only when one exists further on, so the scan
    is linear, and a word with more single-character units than the longest
    candidate name cannot match any of them.
    """
    units, at, end = [], 0, len(pattern)
    last_close = pattern.rfind(']')
    singles = 0
    while at < end:
        char = pattern[at]
        at += 1
        if char == '*':
            if not units or units[-1] != '*':
                units.append('*')
            continue
        singles += 1
        if singles > longest:
            return None
        if char == '?':
            units.append('?')
            continue
        if char == '[':
            start = at + (at < end and pattern[at] == '!')
            start += start < end and pattern[start] == ']'
            if start <= last_close:
                close = pattern.find(']', start)
                body = pattern[at:close]
                negate = body.startswith('!')
                body = body[1:] if negate else body
                spans, k = [], 0
                while k < len(body):
                    if k + 2 < len(body) and body[k + 1] == '-':
                        spans.append((body[k], body[k + 2]))
                        k += 3
                    else:
                        spans.append((body[k], body[k]))
                        k += 1
                units.append((negate, tuple(spans)))
                at = close + 1
                continue
        units.append(char)
    return units


def _ps_glob_unit_matches(unit, char):
    if unit == '?':
        return True
    if isinstance(unit, str):
        return unit == char
    negate, spans = unit
    return any(low <= char <= high for low, high in spans) != negate


def _ps_glob_matches(pattern, names):
    """Return the names a PowerShell/fnmatch-style wildcard word matches."""
    names = sorted(names)
    units = _ps_glob_units(pattern, max(map(len, names)))
    if units is None:
        return []
    matched = []
    for name in names:
        reach = [True] + [False] * len(name)
        for unit in units:
            if unit == '*':
                for k in range(1, len(reach)):
                    reach[k] = reach[k] or reach[k - 1]
                continue
            reach = [False] + [reach[k] and _ps_glob_unit_matches(unit, name[k]) for k in range(len(name))]
        if reach[-1]:
            matched.append(name)
    return matched


def _ps_known_command(value):
    name = value.lower().replace('\\', '/').rsplit('/', 1)[-1]
    if name in _PS_COMMAND_NAMES:
        return name
    if any(char in name for char in '*?['):
        matches = _ps_glob_matches(name, _PS_HOST)
        if matches:
            return matches[0]
    return ''


def _ps_normalize_tokens(tokens, dialect):
    """Normalize static argv spellings once; retain quoted program/data values."""
    values, files = [{}], [{}]
    output = _PsTokens()
    at = 0
    tool = ''
    param_ends = set()
    has_copied = False
    def lookup(scopes, name):
        return next((scope[name] for scope in reversed(scopes) if name in scope), None)
    while at < len(tokens):
        if not at % 16:
            _ps_check_work()
        kind, value = tokens[at]
        if _ps_name(tokens, at) in _PS_FETCH and _ps_position(tokens, at):
            tool = _ps_name(tokens, at)
        elif kind == 'symbol' and value in (';', '|', '{', '}'):
            tool = ''
        if kind == 'word' and value.startswith('-') and value not in ('-P','-I','-L','-E') and tool not in ('curl','curl.exe','wget','wget.exe','aria2c','xh','http'):
            value = value.lower()
        if value == 'param' and at + 1 < len(tokens) and tokens[at + 1][1] == '(' and _ps_position(tokens, at):
            param_ends.add(_ps_group_end(tokens, at + 1))
        if value in ('-i','-I') and at + 2 < len(tokens) and tokens[at + 1:at + 3] == [('symbol', '{'), ('symbol', '}')]:
            output.append(('word', value+'{}'))
            at += 3
            continue
        if (kind, value) == ('symbol', '{'):
            values.append({})
            files.append({})
        elif (kind, value) == ('symbol', '}') and len(values) > 1:
            values.pop()
            files.pop()
        if kind == 'symbol' and value != '&':
            output.append((kind, value))
            if at in param_ends:
                output.append(('symbol', ';'))
            at += 1
            continue
        if kind == 'word' and at + 2 < len(tokens) and tokens[at + 1] == ('symbol', '=') and re.fullmatch(r'\$?[a-z_][\w:]*', value):
            rhs = tokens[at + 2][1]
            scalar_end = at + 3 == len(tokens) or tokens[at + 3][1] in (';', '|', '&', '}')
            literal = scalar_end and len(rhs) <= 4096 and not any(char in rhs for char in '$`') and rhs.lower() not in _PS_FETCH and tokens[at + 2][0] != 'symbol'
            values[-1][value.lstrip('$').lower()] = rhs if literal else None
        # Long program/data arguments cannot name a literal executable. Avoid
        # multiplying their variable references into unbounded temporary text.
        if kind != 'string' and len(value) <= 4096 and ('$' in value or '%' in value):
            expanded = re.sub(r'\$\{([\w:]+)\}|\$([A-Za-z_][\w:]*)|%([A-Za-z_]\w*)%',
                              lambda m: lookup(values, next(part for part in m.groups() if part).lower()) or m[0], value)
            if _ps_known_command(expanded) or (expanded != value and re.search(r'[/\\.]', expanded)):
                value = expanded
        if kind in ('string', 'double') and value.startswith(('-', '/')) and not any(char.isspace() for char in value):
            kind = 'word'
            if value not in ('-P','-I','-L','-E') and tool not in ('curl','curl.exe','wget','wget.exe','aria2c','xh','http'):
                value = value.lower()
        command = _ps_known_command(value)
        if command and (_ps_position(tokens, at) or kind == 'word'):
            kind, value = 'word', command
        copied = lookup(files, _ps_path(value)) if has_copied else None
        if copied and _ps_position(tokens, at):
            kind, value = 'word', copied
        if value in ('cp', 'ln') and _ps_position(tokens, at):
            args, end = [], at + 1
            while end < len(tokens) and tokens[end][0] != 'symbol':
                if not tokens[end][1].startswith('-'):
                    args.append(tokens[end][1])
                end += 1
            if len(args) >= 2 and _ps_known_command(args[0]) in _PS_HOST:
                files[-1][_ps_path(args[-1])] = _ps_known_command(args[0])
                has_copied = True
        if value == '-s' and output and output[-1][1] == 'env' and at + 1 < len(tokens) and tokens[at + 1][0] in ('string', 'double'):
            output.extend(_ps_tokens(tokens[at + 1][1], 'shell'))
            at += 2
            continue
        if value == '&' and at + 4 < len(tokens) and tokens[at + 1][1] == '(' and tokens[at + 2][1] in ('gcm', 'get-command') and tokens[at + 4][1] == ')':
            names = _ps_glob_matches(tokens[at + 3][1].lower(), _PS_EXEC | _PS_HOST)
            if names and (all(name in _PS_EXEC for name in names) or all(name in _PS_HOST for name in names)):
                output.append(('word', names[0]))
                at += 5
                continue
        if _ps_command_flag(value) and ':' in value:
            flag, body = value.split(':', 1)
            output.extend((('word', flag), ('string', body)))
        else:
            output.append((kind, value))
        if at in param_ends:
            output.append(('symbol', ';'))
        at += 1
    return _ps_tuple_assignments(output)


def _ps_tuple_assignments(tokens):
    """Pair static multiple-assignment targets with top-level RHS values."""
    if not any(value == ',' for _, value in tokens):
        return tokens
    output = _PsTokens()
    at = 0
    while at < len(tokens):
        if not at % 16:
            _ps_check_work()
        first = at
        targets = []
        if at == 0 or tokens[at - 1][1] in (';', '{', '(', 'then', 'do', 'else'):
            while at < len(tokens) and re.fullmatch(r'\$[\w:]+', tokens[at][1]):
                targets.append(tokens[at])
                at += 1
                if at < len(tokens) and tokens[at][1] == ',':
                    at += 1
                else:
                    break
        if len(targets) > 1 and at < len(tokens) and tokens[at][1] == '=':
            at += 1
            values, begin, balance = [], at, 0
            while at < len(tokens):
                value = tokens[at][1]
                if value in ('(', '{'): balance += 1
                elif value in (')', '}'):
                    if balance == 0: break
                    balance -= 1
                if balance == 0 and value in (',', ';'):
                    values.append(tokens[begin:at]); begin = at + 1
                    if value == ';': break
                at += 1
            if begin < at: values.append(tokens[begin:at])
            if len(values) == len(targets):
                for number, (target, rhs) in enumerate(zip(targets, values)):
                    if number: output.append(('symbol', ';'))
                    output.extend([target, ('symbol', '=')]); output.extend(rhs)
                continue
        at = first
        output.append(tokens[at]); at += 1
    return output


def _ps_render(tokens):
    import shlex
    return ' '.join(shlex.quote(value) if kind in ('string','double') else value for kind, value in tokens)


def _ps_launcher_program(tokens, index, stop=None):
    """Inspect only a launcher's shell-string field, without copying plain argv."""
    name = _ps_name(tokens, index)
    stop = len(tokens) if stop is None else stop
    at, lock_seen = index + 1, False
    while at < stop:
        option = tokens[at][1]
        if name == 'flock' and option in ('-c','--command'):
            if at + 1 < stop:
                yield tokens[at + 1][1], 'shell'
            return
        if option.startswith('-'):
            at += 1
            if option == '--': break
            if option in _PS_LAUNCH_OPTIONS.get(name, ()):
                at += 1
            continue
        if name == 'flock' and not lock_seen:
            lock_seen = True
            at += 1
            continue
        break
    if name == 'watch' and at < stop and tokens[at][0] in ('string','double'):
        argv = tokens[at:stop]
        direct = any(value in ('-x','--exec') for _, value in tokens[index + 1:at])
        yield (_ps_render(argv) if direct else ' '.join(value for _, value in argv)), 'shell'


def _ps_process_fields(tail):
    """Locate Start-Process executable and argv fields without consuming argv."""
    args_at = next((i for i, (_, value) in enumerate(tail) if value in ('-argumentlist','-args')), None)
    path_at = next((i for i, (_, value) in enumerate(tail[:-1]) if value == '-filepath'), None)
    if path_at is not None:
        return path_at + 1, args_at if args_at is not None else path_at + 1
    end = len(tail) if args_at is None else args_at
    at = 0
    values = ('-verb','-credential','-windowstyle','-workingdirectory','-redirectstandardoutput','-redirectstandarderror','-redirectstandardinput')
    while at < end:
        kind, value = tail[at]
        if value.startswith('-'):
            at += 2 if value in values else 1
        elif kind == 'symbol':
            at += 1
        else:
            return at, args_at if args_at is not None else at
    return None, args_at


def _ps_embedded_programs(tokens, index, stop=None):
    """Read argv/code fields only from known execution interfaces."""
    name = _ps_name(tokens, index)
    if name in ('watch','flock'):
        yield from _ps_launcher_program(tokens, index, stop)
        return
    tail = tokens[index + 1:stop]
    if name in ('start-process', 'saps'):
        host_at, args_at = _ps_process_fields(tail)
        if host_at is not None and args_at is not None and _ps_known_command(tail[host_at][1]) in _PS_HOST:
            args = []
            for kind, value in tail[args_at + 1:]:
                if kind == 'word' and value in ('-wait', '-verb', '-windowstyle', '-nonewwindow', '-passthru'):
                    break
                if kind != 'symbol' and value != '@':
                    args.append(value)
            yield _ps_known_command(tail[host_at][1]) + ' ' + ' '.join(args), 'powershell'
    elif name in ('ssh', 'docker', 'podman', 'kubectl'):
        at = 0
        if name in ('docker', 'podman', 'kubectl'):
            if not tail or tail[0][1] not in ('run', 'exec'):
                return
            at = 1
        value_flags = ('-o','-p','-i','-l','-f','-j') if name == 'ssh' else ('--user','-u','--env','-e','--workdir','-w','--name','--network','-c','--container','-n','--namespace')
        while at < len(tail) and tail[at][1].startswith('-'):
            flag = tail[at][1]
            at += 1
            if at < len(tail) and tail[at][1] == '=':
                at += 2
            elif flag in value_flags:
                at += 1
                if at < len(tail) and tail[at][1] == '=':
                    at += 2
        at += 1  # remote hostname, container or image
        while at < len(tail) and tail[at][1].startswith('-'):
            flag = tail[at][1]; at += 1
            if flag == '--': break
            if flag in value_flags: at += 1
        if at < len(tail):
            yield (' '.join(value for _, value in tail[at:]) if name == 'ssh' else _ps_render(tail[at:])), 'shell'
    elif name in ('su', 'find', 'parallel'):
        if name == 'su':
            for at, (_, value) in enumerate(tail[:-1]):
                if value in ('-c', '--command'):
                    yield tail[at + 1][1], 'shell'
        elif name == 'find':
            for at, (_, value) in enumerate(tail):
                if value in ('-exec', '-execdir'):
                    end = next((j for j in range(at + 1, len(tail)) if tail[j][1] in (';', '+', '\\')), len(tail))
                    yield _ps_render(tail[at + 1:end]), 'shell'
        else:
            split = next((at for at, (_, value) in enumerate(tail) if value == ':::'), None)
            if split is not None:
                at = 0
                while at < split and tail[at][1].startswith('-'):
                    option = tail[at][1]; at += 1
                    if option == '--': break
                    if option in ('-j','--jobs','-S','--sshlogin','--sshloginfile','-a','--arg-file','-N','--max-args','--colsep','--delay'):
                        at += 1
                prefix = _ps_render(tail[at:split])
                for kind, argument in tail[split + 1:]:
                    if kind != 'symbol':
                        yield prefix + ' ' + repr(argument) if prefix else argument, 'shell'
    elif name.endswith('::start') and ('process]' in name):
        args = [value for kind, value in tail if kind != 'symbol' and value != '@']
        if len(args) >= 2 and _ps_known_command(args[0]) in _PS_HOST:
            yield _ps_known_command(args[0]) + ' ' + args[1], 'powershell'
    elif name == 'wmic' and [value for _, value in tail[:3]] == ['process', 'call', 'create']:
        if len(tail) > 3:
            yield tail[3][1], 'shell'
    elif name == 'schtasks':
        for at, (_, value) in enumerate(tail[:-1]):
            if value == '/tr':
                yield tail[at + 1][1], 'shell'
    elif name == 'reg' and tail and tail[0][1] == 'add' and any(re.search(r'[/\\]run(?:once)?$', value, re.I) for _, value in tail):
        for at, (_, value) in enumerate(tail[:-1]):
            if value == '/d':
                yield tail[at + 1][1], 'shell'
    elif name in ('invoke-wmimethod', 'invoke-cimmethod') and any(value == 'win32_process' for _, value in tail) and any(value == 'create' for _, value in tail):
        for at, (_, value) in enumerate(tail[:-1]):
            if value == '-argumentlist':
                yield tail[at + 1][1], 'shell'
            if value == 'commandline' and at + 2 < len(tail):
                yield tail[at + 2][1], 'shell'


def _ps_name(tokens, index):
    _ps_tick()
    kind, value = tokens[index]
    # Quoted names are invoked ONLY after &, never just because text names a tool.
    if kind in ('string', 'double') and not (index and tokens[index - 1] in (('symbol', '&'), ('word', '.'))):
        return ''
    if kind not in ('word', 'string', 'double'):
        return ''
    return value.lower().replace('`', '').replace('\\', '/').rsplit('/', 1)[-1]


def _ps_fetches(tokens, functions=()):
    _ps_tick()
    for i, (kind, value) in enumerate(tokens):
        if not i % 16:
            _ps_check_work()
        name = _ps_name(tokens, i)
        if name in _PS_FETCH or name in functions:
            # Require a command/expression position, not an argument or URL.
            if _ps_position(tokens, i):
                return True
        if kind == 'word' and any(member in value for member in ('.downloadstring', '.downloadfile', '.downloaddata', '.getstringasync', '.openread', '[net.webrequest]::create')) and (value.startswith(('$', '[net.webrequest]')) or (value.startswith('.') and i and tokens[i - 1][1] == ')')):
            return True
    return False


def _ps_subexpressions(value):
    i = 0
    while i < len(value):
        if value[i] == '`':
            i += 2
        elif value.startswith('$(', i):
            start, balance = i + 2, 1
            i += 2
            while i < len(value) and balance:
                if value[i] == '`':
                    i += 2
                    continue
                if value[i] == '(':
                    balance += 1
                elif value[i] == ')':
                    balance -= 1
                i += 1
            yield value[start:i - 1] if not balance else value[start:i]
        else:
            i += 1


def _ps_pipe_before(tokens, index, start):
    if not isinstance(tokens, _PsTokens):
        tokens = _PsTokens(tokens)
    begin = tokens.statement_start(index, start)
    pipe = begin - 1
    if pipe >= start and tokens[pipe] == ('symbol', '&'):
        pipe -= 1  # A PowerShell call operator preserves the upstream pipe.
    return pipe >= start and tokens[pipe] == ('symbol', '|') and _ps_position(tokens, index, begin)


def _ps_inline_executes_input(program, host):
    """Recognize executable input, separately from an inline data processor."""
    if host in ('python', 'python3'):
        import ast
        try:
            tree = ast.parse(program)
        except (MemoryError, RecursionError):
            raise _PsInspectionLimit('Python parser complexity limit exceeded; split the command') from None
        except (SyntaxError, ValueError):
            return False
        tainted = set()
        def reads(node):
            return any((isinstance(part, ast.Attribute) and isinstance(part.value, ast.Name) and part.value.id == 'sys' and part.attr == 'stdin') or
                       (isinstance(part, ast.Name) and part.id in tainted) or
                       (isinstance(part, ast.Call) and isinstance(part.func, ast.Name) and part.func.id == 'input')
                       for part in ast.walk(node))
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        if reads(statement.value): tainted.add(target.id)
                        else: tainted.discard(target.id)
            for call in ast.walk(statement):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in ('exec', 'eval') and call.args and reads(call.args[0]):
                    return True
        return False
    code = _QUOTED_SPAN.sub(' ', program)
    return bool(re.search(r'\b(?:eval|exec)\b', code) and
                re.search(r'stdin|readfilesync\s*\(\s*0|<\s*>', code, re.I))


def _ps_interpreter_uses_download(tokens, index, stop, host):
    """A pipe supplies code only when no module, inline program or script does."""
    at = index + 1
    while at < stop:
        kind, value = tokens[at]
        if (kind == 'symbol' and value in ('|', ';', '&', ')', '}')):
            break
        if value in ('>', '>>', '2>', '2>>'):
            at += 2
            continue
        if value == '<':
            return False
        if value == '--':
            return at + 1 == stop or tokens[at + 1][1] == '-'
        if value == '-':
            return True
        if value in ('--help', '--version', '-h'):
            return False
        if host in ('python', 'python3') and value.startswith('-m'):
            return False
        inline = value in (('-c',) if host in ('python', 'python3') else ('-e', '-E', '--eval', '-p', '--print'))
        if host in _PS_SHELL and _ps_code_flag(value, host):
            inline = True
        if host == 'perl' and re.fullmatch(r'-[A-Za-z]+', value) and 'e' in value[1:]:
            inline = True
        if inline:
            program_at = at + 1
            if program_at < stop and tokens[program_at][1] == '=':
                program_at += 1
            if program_at < stop and host in _PS_SHELL:
                program = tokens[program_at][1]
                for before in range(index):
                    option = tokens[before][1]
                    if option.lower().startswith('-i') and len(option) > 2 and option[2:] in program and any(_ps_name(tokens, j) == 'xargs' and _ps_position(tokens, j) for j in range(before)):
                        return True
            return program_at < stop and _ps_inline_executes_input(tokens[program_at][1], host)
        if not value.startswith('-'):
            return False
        if at + 1 < stop and tokens[at + 1][1] == '=':
            at += 3
            continue
        if value in ('-W', '-X', '-I', '-r', '--require', '--import', '--loader', '--input-type'):
            at += 1
        at += 1
    return True


_PS_HEREDOC_OP = re.compile(r'''<<(-?)[ \t]*(?:'([^'\r\n]+)'|"([^"\r\n]+)"|([A-Za-z_]\w*))(?=\s|$|[<>|;&()])''')


def _ps_heredoc_directives(line):
    """Read operators once, preserving spans and delimiter quoting."""
    i = 0
    result = []
    while i < len(line):
        c = line[i]
        if c == '#':
            break
        if c == '\\':
            i += 2
            continue
        if c in "'\"":
            quote = c
            i += 1
            while i < len(line):
                if quote == '"' and line[i] == '\\':
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if line.startswith('<<', i) and (i == 0 or line[i - 1] != '<') and line[i + 2:i + 3] != '<':
            match = _PS_HEREDOC_OP.match(line, i)
            if match:
                if len(result) >= 256:
                    raise _PsInspectionLimit('heredoc fragment count limit exceeded; split the command')
                result.append((match[2] or match[3] or match[4], bool(match[1]), i, match.end(), match[4] is None))
                i = match.end()
                continue
        i += 1
    return result


def _ps_literal_heredoc_directives(line):
    return ((delimiter, tabs) for delimiter, tabs, _, _, quoted in _ps_heredoc_directives(line) if quoted)


def _ps_remove_heredoc_operators(line, directives=None):
    directives = _ps_heredoc_directives(line) if directives is None else directives
    result, start = [], 0
    for _, _, begin, end, _ in directives:
        result.extend((line[start:begin], ' '))
        start = end
    result.append(line[start:])
    return ''.join(result)


def _ps_shell_quote_state(line, quote=None):
    i = 0
    while i < len(line):
        c = line[i]
        if quote is None and c == '#':
            break
        if c == '\\' and quote != "'":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        i += 1
    return quote


def _ps_without_literal_heredocs(command):
    """Hide document input, retaining expansions and bodies read back as code."""
    if '<<' not in command:
        return command
    lines = command.splitlines(keepends=True)
    output, quote, i = [], None, 0
    offsets, offset = [], 0
    for line in lines:
        offsets.append(offset)
        offset += len(line)
    offsets.append(offset)
    references, basenames = {}, {}
    for match in re.finditer(r'''[^\s'"<>|;&(){}=,]+''', command):
        name = match[0].lower().replace('\\', '/')
        if name.startswith('./'):
            name = name[2:]
        references[name] = match.end()
        basenames[name.rsplit('/', 1)[-1]] = match.end()
    latest_sink = None
    def read_after(path, position):
        nonlocal latest_sink
        name = path.lower().replace('\\', '/')
        if name.startswith('./'):
            name = name[2:]
        if references.get(name, -1) <= position:
            return False
        if latest_sink is None:
            view = _ps_tokens(_ps_shell_hosts(command[position:]))
            sinks = _PS_HOST | _PS_SHELL | _PS_EXEC | frozenset(('source', '.', 'eval', 'exec', 'python', 'python3', 'node', 'perl', 'ruby', 'chmod'))
            latest_sink = max((basenames.get(_ps_name(view, at), -1) for at in range(len(view)) if _ps_name(view, at) in sinks and _ps_position(view, at)), default=-1)
        return latest_sink > position
    while i < len(lines):
        if not i % 16:
            _ps_check_work()
        line = lines[i]
        inside_quote = quote is not None
        quote = _ps_shell_quote_state(line, quote)
        output.append(line)
        i += 1
        if inside_quote:
            continue
        directives = _ps_heredoc_directives(line)
        if not directives:
            continue
        header = _ps_remove_heredoc_operators(line, directives)
        consumer = bool(re.match(r'^\s*(?:cat|tee)\b', header) and not re.search(r'[;&]', header))
        if '|' in header:
            consumer = consumer and bool(re.search(r'\|\s*(?:gh\s+[^\n]*(?:--body-file|-F)\s+-|git\s+[^\n]*-F\s+-)\s*$', header))
        consumer = consumer or bool(re.match(r'^\s*(?:gh|git)\s+[^\n]*(?:--body-file|-F)\s+-\s*$', header))
        consumer = consumer or bool(re.match(r'^\s*(?:curl|http|xh)\b', header) and re.search(r'(?:-d|--data(?:-binary|-raw)?|--json|-T|--upload-file)\s*@-', header))
        # A later read of a written target makes the document exemption unsafe.
        target = re.search(r'(?:>\s*|\btee\s+(?:-a\s+)?)([^\s<>]+)', header)
        header_index = len(output) - 1
        for delimiter, strip_tabs, _, _, quoted in directives:
            body = []
            closed = False
            while i < len(lines):
                check = lines[i].rstrip('\r\n')
                if strip_tabs:
                    check = check.lstrip('\t')
                if check == delimiter:
                    i += 1
                    closed = True
                    break
                body.append(lines[i])
                i += 1
            reused = bool(target and read_after(target.group(1).strip("'\""), offsets[i]))
            if target and re.search(r'(?:\$profile|(?:^|/)(?:\.profile|\.bashrc|\.bash_profile|\.zshrc|profile\.ps1))', target.group(1), re.I):
                reused = True  # Startup files are executable at the next session.
            text = ''.join(body)
            # Python source is data to the shell lexer. Only literal shell
            # strings passed to a top-level Python shell call execute as shell.
            python_body = bool(re.match(r'^\s*python(?:3(?:\.\d+)?)?\s+-\s*$', header.strip()) or
                               (target and reused and target.group(1).strip("'\"").endswith('.py') and max(basenames.get('python', -1), basenames.get('python3', -1)) > offsets[i]))
            if python_body and closed and not re.search(r'\bos\s*\.\s*system\s*\(', text):
                # No supported shell call exists, so parsing the entire Python
                # test program cannot add executable-shell evidence.
                output[header_index] = header
                output.append('\n')
                continue
            if python_body and closed:
                import ast
                try:
                    tree = ast.parse(text)
                except (MemoryError, RecursionError):
                    raise _PsInspectionLimit('Python parser complexity limit exceeded; split the command') from None
                except (SyntaxError, ValueError):
                    pass
                else:
                    commands = []
                    for node in tree.body:
                        call = node.value if isinstance(node, ast.Expr) else None
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and call.func.value.id == 'os' and call.func.attr == 'system' and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                            commands.append(call.args[0].value)
                    output[header_index] = header
                    output.append('\n' + '\n'.join(commands) + '\n')
                    continue
            # Expanding heredocs execute substitutions even for document sinks.
            expansion = not quoted and ('$' + '(' in text or '`' in text)
            if consumer and closed and not reused and not expansion:
                output[header_index] = header
                output.append('\n')
            else:
                output.append(text)
                if closed:
                    output.append(lines[i - 1])
    return ''.join(output)


# Text transformations and indexed/container values keep remote provenance.
# Known scalar members (.Length, .Contains(), .name) do not carry code text.
_PS_SCALAR_MEMBERS = frozenset(('length', 'count', 'name', 'contains', 'indexof', 'gethashcode', 'equals', 'compareto', 'startswith', 'endswith'))
# Casts that produce a plain value (Boolean, number, date, ...) and so drop the
# payload text. Every other cast, including unknown ones, keeps the text; array
# casts also make the value a collection.
_PS_SANITIZING_CASTS = frozenset((
    'bool', 'boolean', 'system.boolean', 'int', 'int16', 'int32', 'int64', 'uint16', 'uint32', 'uint64',
    'long', 'ulong', 'short', 'ushort', 'byte', 'sbyte', 'double', 'float', 'single', 'decimal',
    'system.int16', 'system.int32', 'system.int64', 'system.uint16', 'system.uint32', 'system.uint64',
    'system.double', 'system.single', 'system.decimal', 'system.byte', 'system.sbyte',
    'char', 'system.char', 'datetime', 'system.datetime', 'timespan', 'system.timespan',
    'guid', 'system.guid', 'version', 'system.version'))
_PS_ARRAY_CASTS = frozenset(('array', 'system.array'))

_PS_INTERPOLATED = re.compile(r'(?<!`)\$(?:\{([^}]*)\}|([\w:]+))')


_PS_CAST_ONE = r'\[((?:[^\[\]]|\[[^\[\]]*\])*)\]'
_PS_CAST = re.compile(r'^(?:' + _PS_CAST_ONE + r')+')


def _ps_cast_info(value):
    """(drops the text, collection shape: True, False or None for unchanged) for a word's leading [type] casts."""
    match = _PS_CAST.match(value)
    names = [c.strip().lower() for c in re.findall(_PS_CAST_ONE, match.group(0))] if match else []
    if not names:
        return False, None
    sanitizes = any(n in _PS_SANITIZING_CASTS for n in names)
    # The left-most cast that sets a shape (applied last) decides it: an array
    # cast makes a collection, [string] joins into one string, others keep it.
    for n in names:
        if n.endswith('[]') or n in _PS_ARRAY_CASTS:
            return sanitizes, True
        if n in ('string', 'system.string'):
            return sanitizes, False
    return sanitizes, None


def _ps_text_cast(value):
    """True when the leading [type] casts on a word keep the payload text (or there are none)."""
    return not _ps_cast_info(value)[0]


def _ps_assignments(tokens, start, stop):
    """Find `$a = $b = <rhs>` (also `[type]$a`, `$a += <rhs>`) in tokens[start:stop].

    Candidates start at the segment start and after every `(` or `{`, so
    `($b=$a)` and `if (...) { $b=$a }` are seen. The RHS runs to the next `;`
    outside brackets, so a multiline `$b = (` ... `)` stays one value.
    Yields (targets, rhs tokens, append, index of the first target).
    """
    starts = [start] + [i + 1 for i in range(start, stop) if tokens[i] in (('symbol', '{'), ('symbol', '('), ('word', 'then'), ('word', 'do'), ('word', 'else'))]
    for first in starts:
        targets, shapes, sans, append, i = [], [], [], False, first
        while i < stop:
            k, casts = i, []
            while k < stop and tokens[k][0] == 'word' and _PS_CAST.fullmatch(tokens[k][1]):
                casts.append(tokens[k][1])
                k += 1
            if casts and not (k < stop and tokens[k][0] == 'word' and tokens[k][1].startswith('$')):
                break  # a cast that is not applied to a target
            here = not all(_ps_text_cast(c) for c in casts)
            if k >= stop or tokens[k][0] != 'word':
                break
            here = here or not _ps_text_cast(tokens[k][1])
            name, j = _PS_CAST.sub('', tokens[k][1]), k + 1
            if not name.startswith('$'):
                break
            plus = name.endswith('+')
            if not plus and j < len(tokens) and tokens[j] == ('word', '+'):
                plus, j = True, j + 1
            if j >= len(tokens) or tokens[j] != ('symbol', '='):
                break
            sans.append(here)
            shapes.append(_ps_cast_info(''.join(casts) + tokens[k][1])[1])
            targets.append(name.rstrip('+'))
            append = append or plus
            i = j + 1
        if not targets or i >= len(tokens):
            continue
        depth, end = 0, i
        while end < len(tokens):
            if not end % 16:
                _ps_check_work()
            kind, value = tokens[end]
            if kind == 'symbol' and value in ('(', '{'):
                depth += 1
            elif kind == 'symbol' and value in (')', '}'):
                depth -= 1
                if depth < 0 and first != start:
                    break
            elif tokens[end] == ('symbol', ';') and depth <= 0:
                break
            end += 1
        # `sans[n]` marks a target whose own cast stores a value, not the payload text.
        yield targets, tokens[i:end], append, first, shapes, sans


def _ps_brace_scopes(tokens):
    """Per token: innermost brace kind ('def', 'flow' or None) and the tuple of
    enclosing definition-brace indexes. A `{` that follows `function name`,
    `=` (script block literal) or `@` (hashtable) only defines code or data;
    other braces (if/foreach/try/...) run in place.
    """
    # Pair parentheses once. Bash case patterns contain unmatched ')' tokens;
    # walking backwards from each one made ordinary padding quadratic.
    pairs, parens = {}, []
    for index, token in enumerate(tokens):
        if not index % 16:
            _ps_check_work()
        if token == ('symbol', '('):
            parens.append(index)
        elif token == ('symbol', ')') and parens:
            pairs[index] = parens.pop()
    kinds, chains, stack, chain = [], [], [], ()
    for i, token in enumerate(tokens):
        if not i % 16:
            _ps_check_work()
        kinds.append(stack[-1][1] if stack else None)
        chains.append(chain)
        if token == ('symbol', '{'):
            p, definition = i - 1, False
            if p >= 0 and tokens[p] == ('symbol', ')'):
                p = pairs.get(p, 0) - 1
                definition = p >= 1 and tokens[p - 1][1] in ('function', 'filter', 'workflow')
            elif p >= 0:
                definition = (tokens[p] == ('symbol', '=') or tokens[p][1].endswith('@')
                              or (p >= 1 and tokens[p - 1][1] in ('function', 'filter', 'workflow')))
            stack.append((i, 'def' if definition else 'flow'))
            if definition:
                chain = chain + (i,)
        elif token == ('symbol', '}') and stack:
            index, kind = stack.pop()
            if kind == 'def':
                chain = chain[:-1]
    return kinds, chains


def _ps_copy_source(value):
    """Keep text/container provenance, excluding known scalar-result members."""
    if _ps_cast_info(value)[0]:
        return None
    value = _PS_CAST.sub('', value)
    if re.fullmatch(r'@[\w:]+', value):
        value = '$' + value[1:]
    match = re.match(r'\$[\w:]+', value)
    if not match:
        return None
    rest = value[match.end():]
    if not rest.strip('+') or rest.startswith('['):
        return match.group(0)
    if rest.startswith('.') and rest[1:] not in _PS_SCALAR_MEMBERS:
        return match.group(0)
    return None


_PS_RESULT_OP = re.compile(r'-[ci]?(?:contains|notcontains|in|notin|is|isnot|and|or|xor|not)$|-(?:band|bor|bxor|bnot|shl|shr)$')
_PS_FILTER_OP = re.compile(r'-[ci]?(?:eq|ne|gt|lt|ge|le|like|notlike|match|notmatch)$')


def _ps_group_end(tokens, i):
    """Index of the bracket closing tokens[i], or len(tokens) when unbalanced."""
    depth = 0
    for j in range(i, len(tokens)):
        if not j % 16:
            _ps_check_work()
        if tokens[j][0] == 'symbol' and tokens[j][1] in ('(', '{'):
            depth += 1
        elif tokens[j][0] == 'symbol' and tokens[j][1] in (')', '}'):
            depth -= 1
            if depth == 0:
                return j
    return len(tokens)


def _ps_top_level(tokens, test):
    """First index of a token at bracket depth 0 for which test(token) holds."""
    i = 0
    while i < len(tokens):
        if not i % 16:
            _ps_check_work()
        if tokens[i][0] == 'symbol' and tokens[i][1] in ('(', '{'):
            i = _ps_group_end(tokens, i)
        elif test(tokens[i]):
            return i
        i += 1
    return -1


class _PsView:
    """Read-only union of name sets (top level plus enclosing function bodies).

    Sets are shared, never copied, so memory stays flat however many
    assignments a body has.
    """
    __slots__ = ('sets',)

    def __init__(self, sets):
        self.sets = sets

    def __contains__(self, name):
        return any(name in names for names in self.sets)

    def __bool__(self):
        return any(self.sets)

    def isdisjoint(self, names):
        names = list(names)
        return all(group.isdisjoint(names) for group in self.sets)


def _ps_expr(tokens, remote_vars, collection_vars, dialect='shell', depth=0):
    """Judge an expression by its result: (may carry payload text, collection-shaped).

    Scalar Boolean/numeric results (-and, -or, -not, -contains, -in, -is, a
    scalar -eq/-like/-match, [bool]/[int] casts) are not payload. Comparison
    operators on a collection FILTER it and keep the text, and concatenation
    or any other operator keeps text from any operand. Collection shape is
    tracked even for clean values, because text appended later joins it.
    Interpolation always yields a string. Unsure means tainted.
    """
    if depth > 16:
        # Too deeply nested to judge cheaply: assume any mention keeps the text.
        return _ps_derives_remote(tokens, remote_vars), True

    def is_op(pattern):
        return lambda token: token[0] == 'word' and pattern.fullmatch(token[1]) is not None
    if _ps_top_level(tokens, is_op(_PS_RESULT_OP)) >= 0:
        return False, False
    # `x -as A -as B` runs left to right, so the last -as converts last.
    as_at, offset = -1, 0
    while True:
        found = _ps_top_level(tokens[offset:], lambda t: t == ('word', '-as'))
        if found < 0:
            break
        as_at = offset + found
        offset = as_at + 1
    if as_at >= 0 and as_at + 1 < len(tokens) and tokens[as_at + 1][0] == 'word' and _PS_CAST.fullmatch(tokens[as_at + 1][1]):
        sanitizes, collection = _ps_cast_info(tokens[as_at + 1][1])
        if sanitizes:
            return False, False
        tainted, left_collection = _ps_expr(tokens[:as_at], remote_vars, collection_vars, dialect, depth + 1)
        return tainted, left_collection if collection is None else collection
    cmp_at = _ps_top_level(tokens, is_op(_PS_FILTER_OP))
    if cmp_at >= 0:
        tainted, collection = _ps_expr(tokens[:cmp_at], remote_vars, collection_vars, dialect, depth + 1)
        return (tainted and collection), collection
    tainted = collection = False
    pending = None  # (sanitizes, shape) of a standalone cast waiting for its operand
    i = 0
    while i < len(tokens):
        if not i % 16:
            _ps_check_work()
        kind, value = tokens[i]
        if kind == 'word' and _PS_CAST.fullmatch(value):
            info = _ps_cast_info(value)
            if pending is not None:
                # Contiguous casts compose: any sanitizer drops the text and the
                # left-most (applied last) cast that sets a shape decides it.
                info = (pending[0] or info[0], pending[1] if pending[1] is not None else info[1])
            pending = info
            i += 1
            continue
        sanitized = pending is not None and pending[0]
        shape = pending[1] if pending is not None else None
        if kind == 'symbol' and value in ('(', '{'):
            end = _ps_group_end(tokens, i)
            inner_t, inner_c = _ps_expr(tokens[i + 1:end], remote_vars, collection_vars, dialect, depth + 1)
            if not sanitized:
                tainted = tainted or inner_t
                collection = collection or (inner_c if shape is None else shape)
            pending = None
            i = end + 1
            continue
        if kind == 'symbol' and value == ',' or (kind == 'word' and value in ('@', '-split', '-csplit', '-isplit')):
            collection = True
        elif kind == 'word':
            sources = [_ps_copy_source(part) for part in value.split('+') if part]
            fused_sanitizes, fused_shape = _ps_cast_info(value)
            if not sanitized and not fused_sanitizes:
                if any(s in remote_vars for s in sources):
                    tainted = True
                explicit = shape if shape is not None else fused_shape
                if explicit is True or (explicit is None and any(s in collection_vars for s in sources)):
                    collection = True
            if not value.startswith('-') and value != '+':
                pending = None
        elif kind == 'double':
            if not sanitized:
                text = value
                for expr in _ps_subexpressions(value):
                    text = text.replace('$(' + expr + ')', '', 1)
                    inner_t, _ = _ps_expr(_ps_tokens(expr, dialect), remote_vars, collection_vars, dialect, depth + 1)
                    tainted = tainted or inner_t
                names = {'$' + (m[0] or m[1]).lower() for m in _PS_INTERPOLATED.findall(text)}
                if not remote_vars.isdisjoint(names):
                    tainted = True
            pending = None
        i += 1
    return tainted, collection


def _ps_derives_remote(tokens, remote_vars):
    """True when a value is built from a remote-fetched variable.

    Covers plain copies ($b=$a, ($a), [string]$a, "$a", $a.Trim()), appends
    and concatenation. Unrelated members ($a.Length) stay untainted.
    """
    _ps_tick()
    if not remote_vars:
        return False
    for kind, value in tokens:
        if kind == 'word' and any(_ps_copy_source(part) in remote_vars for part in value.split('+') if part):
            return True
        if kind == 'double' and not remote_vars.isdisjoint('$' + (m[0] or m[1]).lower() for m in _PS_INTERPOLATED.findall(value)):
            return True
    return False


def _ps_path(value):
    _ps_tick()
    value = value.lower().replace('\\', '/')
    value = re.sub(r'^\$(?:pwd|\{pwd\})/', '', value)
    value = re.sub(r'^/(?:mnt/)?([a-z])/', r'\1:/', value)
    while value.startswith('./'):
        value = value[2:]
    return value


def _ps_reads_remote(tokens, remote_files, clipboard=False):
    for i, (kind, value) in enumerate(tokens):
        if clipboard and value == 'get-clipboard' and _ps_position(tokens, i):
            return True
        reader = value in ('gc', 'get-content', 'cat') and _ps_position(tokens, i)
        reader = reader or (kind == 'word' and value.endswith(('::readalltext', '.readalltext')))
        if reader and any(_ps_path(path) in remote_files for _, path in tokens[i + 1:]):
            return True
    return False


def _ps_download_paths(tokens):
    """Interpret downloader output argv, including default URL basenames."""
    for i in range(len(tokens)):
        if not i % 16:
            _ps_check_work()
        name = _ps_name(tokens, i)
        if name not in _PS_FETCH or not _ps_position(tokens, i):
            continue
        end = i + 1
        while end < len(tokens) and tokens[end][1] not in (';', '|', '&', ')', '}'):
            end += 1
        args = [value for kind, value in tokens[i + 1:end] if kind != 'symbol' or value == '=']
        url = next((value for value in args if re.match(r'https?://', value, re.I)), '')
        filename = url.split('?', 1)[0].rstrip('/').rsplit('/', 1)[-1]
        output, directory, remote_name = None, '', False
        j = 0
        while j < len(args):
            flag = args[j]; j += 1
            key, equal, attached = flag.partition('=')
            output_flag = key in ('--output','--output-document','--out','-OutFile','-outfile','-Destination','-destination')
            directory_flag = key in ('--directory-prefix','--dir','-P') if name.startswith('wget') else key in ('--dir','-d') if name == 'aria2c' else False
            if name.startswith('curl'):
                remote_name = remote_name or key == '--remote-name' or bool(re.fullmatch(r'-[^-]*O[^-]*', key))
                short = re.fullmatch(r'-[^-]*?o(.*)', key)
                if short:
                    output_flag, attached = True, short[1]
            elif name.startswith('wget'):
                short = re.fullmatch(r'-[^-]*?O(.*)', key)
                if short:
                    output_flag, attached = True, short[1]
            elif name in ('aria2c','xh','http') and key == '-o':
                output_flag = True
            if name.startswith('wget') and key.startswith('-P') and len(key) > 2:
                directory_flag, attached = True, key[2:]
            elif name == 'aria2c' and len(key) > 2 and key[:2] in ('-o','-d'):
                output_flag, directory_flag, attached = key[1] == 'o', key[1] == 'd', key[2:]
            elif name in ('xh','http') and key.startswith('-o') and len(key) > 2:
                output_flag, attached = True, key[2:]
            if output_flag or directory_flag:
                if not attached:
                    if j < len(args) and args[j] == '=': j += 1
                    if j < len(args): attached = args[j]; j += 1
                if directory_flag: directory = attached.rstrip('/')
                else: output = attached
        if output is None and (remote_name or name.startswith('wget') or name == 'aria2c' or (name in ('xh','http') and '--download' in args)):
            output = filename
        if output and output != '-':
            yield _ps_path((directory + '/' if directory else '') + output)


def _ps_profile_write(tokens):
    profiles = [i for i, (_, value) in enumerate(tokens) if value.lower().startswith('$profile') or value.lower().replace('\\','/').endswith('microsoft.powershell_profile.ps1')]
    if not profiles:
        return False
    named_writer = any((_ps_name(tokens, i) in ('add-content','ac','set-content','sc','out-file','new-item') and _ps_position(tokens, i)) for i in range(len(tokens)))
    redirect = any(i and tokens[i - 1][1] in ('>','>>') for i in profiles)
    output_writer = redirect and any(_ps_name(tokens, i) in ('echo','printf') and _ps_position(tokens, i) for i in range(len(tokens)))
    if not named_writer and not output_writer:
        return False
    for kind, value in tokens:
        if kind in ('string','double') and (has_pipe_to_shell(value) or detects_powershell_execution(value, dialect='powershell')):
            return True
    return _ps_fetches(tokens) and any(_ps_name(tokens, i) in _PS_EXEC for i in range(len(tokens)))


def _ps_remote_program_input(value, depth=0):
    """Command substitutions yield program text only at a code argv site."""
    _ps_tick()
    if depth > 32:
        raise _PsInspectionLimit('executable nesting limit exceeded')
    expressions = list(_ps_subexpressions(value))
    expressions.extend(match[1] for match in re.finditer(r'`([^`]+)`', value))
    for expression in expressions:
        tokens = _ps_tokens(expression)
        if _ps_fetches(tokens):
            return True
        for i in range(len(tokens)):
            if _ps_name(tokens, i) in _PS_CODE_HOST and _ps_position(tokens, i):
                for j in range(i + 1, len(tokens) - 1):
                    if _ps_code_flag(tokens[j][1], _ps_name(tokens, i)):
                        program = tokens[j + 1][1]
                        if _ps_fetches(_ps_tokens(program)) or _ps_remote_program_input(program, depth + 1):
                            return True
    return False


def _ps_file_flow(tokens, remote_files, clipboard, remote_vars, depth=0):
    """Record remote writes; return whether a later code sink reads them."""
    if depth > 32:
        raise _PsInspectionLimit('executable nesting limit exceeded')
    if _ps_profile_write(tokens):
        return True, clipboard
    remote_files.update(_ps_download_paths(tokens))
    fetched = _ps_fetches(tokens) or _ps_derives_remote(tokens, remote_vars)
    names, remote_url = [], False
    for i, (_, value) in enumerate(tokens):
        if not i % 16:
            _ps_check_work()
        names.append(_ps_name(tokens, i))
        remote_url = remote_url or bool(re.search(r'https?://', value, re.I))
    fetcher = any(n in ('certutil', 'certutil.exe', 'bitsadmin', 'bitsadmin.exe') and _ps_position(tokens, i) for i, n in enumerate(names))
    if fetcher and remote_url:
        fetched = True
        url_at = next(i for i, (_, value) in enumerate(tokens) if re.search(r'https?://', value, re.I))
        if url_at + 1 < len(tokens) and tokens[url_at + 1][0] != 'symbol':
            remote_files.add(_ps_path(tokens[url_at + 1][1]))
    if remote_url and any(n in ('mshta', 'mshta.exe', 'regsvr32', 'regsvr32.exe', 'rundll32', 'rundll32.exe') and _ps_position(tokens, i) for i, n in enumerate(names)):
        return True, clipboard
    redirect = next((i for i, (_, value) in enumerate(tokens) if value in ('>', '>>')), None)
    if redirect is not None and redirect + 1 < len(tokens) and tokens[redirect + 1][0] != 'symbol':
        writer = any(n in ('echo', 'printf') and _ps_position(tokens, i) for i, n in enumerate(names[:redirect]))
        code = writer and any(kind in ('string','double') and (has_pipe_to_shell(value) or detects_powershell_execution(value)) for kind, value in tokens[:redirect])
        if fetched or code:
            remote_files.add(_ps_path(tokens[redirect + 1][1]))
            if tokens[redirect + 1][1].lower() == '$profile':
                return True, clipboard
    if not fetched and not remote_files and not clipboard:
        return False, clipboard
    if fetched and any(name in ('start-bitstransfer', 'sbt') for name in names):
        url_at = next((i for i, (_, value) in enumerate(tokens) if re.search(r'https?://', value, re.I)), None)
        if url_at is not None and url_at + 1 < len(tokens) and not tokens[url_at + 1][1].startswith('-'):
            remote_files.add(_ps_path(tokens[url_at + 1][1]))
    for i, (kind, value) in enumerate(tokens):
        if not i % 16:
            _ps_check_work()
        if fetched and value in ('-outfile', '-o', '-destination') and i + 1 < len(tokens):
            remote_files.add(_ps_path(tokens[i + 1][1]))
            if value == '-o' and re.search(r'https?://', tokens[i + 1][1], re.I):
                remote_files.add(_ps_path(tokens[i + 1][1].rsplit('/', 1)[-1]))
            if tokens[i + 1][1] == '$profile':
                return True, clipboard
        if fetched and value in ('set-content', 'sc', 'out-file', 'add-content', 'ac') and _ps_position(tokens, i) and i + 1 < len(tokens):
            path_at = i + 2 if tokens[i + 1][1] in ('-path', '-literalpath', '-filepath') else i + 1
            while path_at < len(tokens) and tokens[path_at][1].startswith('-'):
                path_at += 1
            if path_at < len(tokens):
                remote_files.add(_ps_path(tokens[path_at][1]))
                if tokens[path_at][1].lower() == '$profile':
                    return True, clipboard
        if fetched and value == '-o' and (i + 1 >= len(tokens) or tokens[i + 1][0] == 'symbol'):
            url = next((value for _, value in tokens if re.search(r'https?://', value, re.I)), '')
            remote_files.add(_ps_path(url.rsplit('/', 1)[-1]))
        if fetched and '.downloadfile' in value:
            end = _ps_group_end(tokens, i + 1) if i + 1 < len(tokens) and tokens[i + 1][1] == '(' else len(tokens)
            comma = next((j for j in range(i + 1, end) if tokens[j][1] == ','), None)
            if comma is not None and comma + 1 < end:
                remote_files.add(_ps_path(tokens[comma + 1][1]))
        if fetched and value == 'set-clipboard' and _ps_position(tokens, i):
            clipboard = True
    # Inspect executable paths and reads, not arbitrary data arguments.
    for i, (kind, value) in enumerate(tokens):
        if not i % 16:
            _ps_check_work()
        name = names[i]
        path_match = _ps_path(value) in remote_files
        if name in ('start-process','saps','watch','flock','wmic','invoke-wmimethod','invoke-cimmethod') or name.endswith('process]::start'):
            if _ps_position(tokens, i):
                if name in ('start-process','saps'):
                    tail = tokens[i + 1:]
                    target, _ = _ps_process_fields(tail)
                    if target is not None and _ps_path(tail[target][1]) in remote_files:
                        return True, clipboard
                for program, dialect in _ps_embedded_programs(tokens, i):
                    nested = _ps_normalize_tokens(_ps_tokens(program, dialect), dialect)
                    if _ps_file_flow(nested, remote_files, clipboard, remote_vars, depth + 1)[0]:
                        return True, clipboard
        if not path_match and name not in _PS_FILE_SINK_NAMES and value != '&':
            continue
        positioned = _ps_position(tokens, i)
        if kind == 'word' and path_match and positioned and (not i or tokens[i - 1][1] != '='):
            return True, clipboard
        if not positioned:
            continue
        tail = tokens[i + 1:]
        if name in _PS_CODE_HOST | _PS_STDIN_HOST | {'wscript', 'cscript'}:
            if name in _PS_SHELL:
                noexec = False
                for _, flag in tail:
                    if not flag.startswith('-') or _ps_code_flag(flag, name):
                        break
                    if flag == '--noexec' or re.fullmatch(r'-[a-z]*n[a-z]*', flag):
                        noexec = True
                if noexec:
                    continue
            if any(value == '<' and at + 1 < len(tail) and _ps_path(tail[at + 1][1]) in remote_files for at, (_, value) in enumerate(tail)):
                return True, clipboard
            first = 0
            while first < len(tail) and tail[first][1].startswith('-'):
                first += 1
            if first < len(tail) and _ps_path(tail[first][1]) in remote_files:
                return True, clipboard
            for at, (k, flag) in enumerate(tail):
                if flag in ('-file', '-f'):
                    if at + 1 < len(tail) and _ps_path(tail[at + 1][1]) in remote_files:
                        return True, clipboard
                    break
                if _ps_code_flag(flag, name) and at + 1 < len(tail) and tail[at + 1][0] in ('string', 'double'):
                    nested = _ps_normalize_tokens(_ps_tokens(_ps_shell_hosts(tail[at + 1][1])), 'shell')
                    if _ps_file_flow(nested, remote_files, clipboard, remote_vars, depth + 1)[0]:
                        return True, clipboard
            if _ps_pipe_before(tokens, i, 0) and _ps_reads_remote(tokens[:i], remote_files, clipboard):
                return True, clipboard
        elif name in _PS_EXEC:
            if any(_ps_path(value) in remote_files for _, value in tail):
                return True, clipboard
            if _ps_reads_remote(tail, remote_files, clipboard):
                return True, clipboard
            if _ps_pipe_before(tokens, i, 0) and _ps_reads_remote(tokens[:i], remote_files, clipboard):
                return True, clipboard
        elif name in ('.', 'source') and tail and (_ps_path(tail[0][1]) in remote_files or (tail[0][1] == '(' and len(tail) > 2 and tail[1][1] == 'resolve-path' and _ps_path(tail[2][1]) in remote_files)):
            return True, clipboard
        elif value == '&' and tail and _ps_path(tail[0][1]) in remote_files:
            return True, clipboard
    return False, clipboard


def _ps_named_writes(tokens, remote_vars, function_returns, owner):
    """Remote-returning commandlets and flow bindings share normal taint."""
    for i, (kind, value) in enumerate(tokens):
        if not i % 16:
            _ps_check_work()
        if value in ('set-variable', 'new-variable', 'sv', 'nv') and _ps_position(tokens, i):
            at = i + 1
            if at < len(tokens) and tokens[at][1] == '-name':
                at += 1
            if at < len(tokens) and (_ps_fetches(tokens[at + 1:]) or _ps_derives_remote(tokens[at + 1:], remote_vars)):
                owner(i).add('$' + tokens[at][1].lower().lstrip('$'))
        if value in ('-outvariable', '-ov', '-variable') and i + 1 < len(tokens):
            if _ps_fetches(tokens[:i]) or _ps_derives_remote(tokens[:i], remote_vars):
                owner(i).add('$' + tokens[i + 1][1].lower().lstrip('+$'))
        if value == 'foreach' and i + 3 < len(tokens) and tokens[i + 2][1].startswith('$'):
            end = _ps_group_end(tokens, i + 1)
            if _ps_fetches(tokens[i + 3:end]) or _ps_derives_remote(tokens[i + 3:end], remote_vars):
                owner(i).add(tokens[i + 2][1])
        if value in ('function', 'filter') and i + 2 < len(tokens):
            brace = next((j for j in range(i + 2, len(tokens)) if tokens[j][1] == '{'), None)
            if brace is not None:
                end = _ps_group_end(tokens, brace)
                if _ps_fetches(tokens[brace + 1:end]) or _ps_derives_remote(tokens[brace + 1:end], remote_vars):
                    function_returns.add(tokens[i + 1][1])


def detects_powershell_execution(command, depth=0, heredocs_masked=False, dialect='shell'):
    """Block coupled remote fetch+execution and opaque EncodedCommand calls.

    This intentionally does not claim general PowerShell deobfuscation or
    dataflow analysis. Recursion is limited to quoted executable code bodies.
    """
    if not command:
        return False
    if depth > 32:
        if _PS_HINT.search(command.replace('`', '')):
            raise _PsInspectionLimit('executable nesting limit exceeded')
        return False
    if dialect == 'shell':
        command = _ps_shell_hosts(command.replace('\0', ' ').replace('\\\n', ''))
    command = re.sub(r'\$\{([\w:]+)\}', r'$\1', command)
    # Reject non-candidates before allocating the lexical view on the hot path.
    hint_text = command.replace('`', '')
    if not _PS_HINT.search(hint_text):
        return False
    if not _PS_CONTENT_HINT.search(hint_text) and not _PS_HOST_SPELLING.search(hint_text):
        return False
    if not heredocs_masked and dialect == 'shell':
        command = _ps_without_literal_heredocs(command)
    tokens = _ps_normalize_tokens(_ps_tokens(command, dialect), dialect)
    if has_pipe_to_shell(command) and not is_inert_quote_carrier(command):
        return True
    if re.search(r'vbscript:', command, re.I) and re.search(r'\b(?:powershell|pwsh)(?:\.exe)?\s+-(?:enc\w*|e|ec)\b', command, re.I):
        if any(_ps_name(tokens, i) in ('mshta', 'mshta.exe') and _ps_position(tokens, i) for i in range(len(tokens))):
            return True
    if re.search(r'javascript:', command, re.I) and re.search(r'mshtml', command, re.I) and re.search(r'script:https?://', command, re.I):
        if any(_ps_name(tokens, i) in ('rundll32', 'rundll32.exe') and _ps_position(tokens, i) for i in range(len(tokens))) and any(value.startswith('javascript:') for _, value in tokens) and any('mshtml' in value.lower() for _, value in tokens):
            return True
    # Inspect only the balanced executable subexpression, not trailing prose.
    for kind, value in tokens:
        if kind == 'double':
            for expression in _ps_subexpressions(value):
                if detects_powershell_execution(expression, depth + 1, dialect=dialect):
                    return True
    # Cheap bracket pairing prevents quadratic rescans of nested expressions.
    ends, stack = {}, []
    for i, (kind, value) in enumerate(tokens):
        if kind == 'symbol' and value == '(':
            stack.append(i)
        elif kind == 'symbol' and value == ')' and stack:
            ends[stack.pop()] = i
    # Resolve only literal command aliases at their call sites. Definitions
    # have their own scope, so an unused function cannot rename outer commands.
    aliases = [{}]
    for i in range(len(tokens)):
        if not i % 16:
            _ps_check_work()
        kind, value = tokens[i]
        if (kind, value) == ('symbol', '{'):
            aliases.append({})
        elif (kind, value) == ('symbol', '}') and len(aliases) > 1:
            aliases.pop()
        elif value in ('set-alias', 'sal', 'new-alias', 'nal') and i + 2 < len(tokens):
            named={};positional=[];at=i+1
            while at<len(tokens) and tokens[at][0]!='symbol':
                flag=tokens[at][1].lower()
                if flag in ('-name','-value') and at+1<len(tokens):
                    named[flag]=tokens[at+1][1];at+=2
                else:positional.append(tokens[at][1]);at+=1
            a=named.get('-name',positional[0] if positional else '')
            b=named.get('-value',positional[1] if len(positional)>1 else '').lower()
            if b in _PS_EXEC | _PS_HOST:
                aliases[-1][a] = b
        elif i + 2 < len(tokens) and kind == 'word' and re.fullmatch(r'\$?[a-z_][\w:]*', value) and tokens[i + 1] == ('symbol', '='):
            b = tokens[i + 2][1].lower()
            aliases[-1]['$' + value.lstrip('$')] = b if b in _PS_EXEC | _PS_HOST else ''
        elif kind == 'word' or (i and tokens[i - 1] == ('symbol', '&')):
            resolved = next((scope[value] for scope in reversed(aliases) if value in scope), '')
            if resolved:
                tokens[i] = ('word', resolved)
    remote_vars, local_vars = set(), {}
    collection_vars, local_shapes = set(), {}
    scoped = any(token == ('symbol', '{') for token in tokens)
    kinds, chains = _ps_brace_scopes(tokens) if scoped else ([], [])

    def view(i, base, locals_):
        """Names seen at token i: top level plus enclosing definitions (no copies)."""
        if not scoped or not chains[i] or not locals_:
            return base
        return _PsView([base] + [locals_[owner] for owner in chains[i] if owner in locals_])

    def visible(i):
        """Remote variables seen at token i."""
        return view(i, remote_vars, local_vars)

    file_scopes, function_returns, clipboards = {}, set(), {}
    pending_scripts = set()
    # Index of the next here-string operator at or after each token, so the
    # per-command `<<<` checks below do not rescan the rest of the statement.
    next_herestring = [len(tokens)] * (len(tokens) + 1)
    for k in range(len(tokens) - 1, -1, -1):
        next_herestring[k] = k if tokens[k][1] == '<<<' else next_herestring[k + 1]
    start = 0
    for stop in range(len(tokens) + 1):
        if not stop % 16:
            _ps_check_work()
        if stop < len(tokens) and tokens[stop] != ('symbol', ';'):
            continue
        if stop == start:
            start = stop + 1
            continue
        segment = tokens[start:stop]
        def owner(index):
            chain = chains[start + index] if scoped else ()
            return local_vars.setdefault(chain[-1], set()) if chain else remote_vars
        _ps_named_writes(segment, visible(start) if start < len(tokens) else remote_vars, function_returns, owner)
        # File/clipboard writes in a definition belong to that definition.
        first = start
        while first < stop:
            chain = chains[first] if scoped else ()
            end = first + 1
            while end < stop and (chains[end] if scoped else ()) == chain:
                end += 1
            files = file_scopes.setdefault(chain, set())
            blocked, clipboards[chain] = _ps_file_flow(tokens[first:end], files, clipboards.get(chain, False), visible(first))
            if blocked:
                return True
            first = end
        for targets, rhs, append, at, target_shapes, target_sans in _ps_assignments(tokens, start, stop):
            seen = visible(at)
            expr_tainted, expr_collection = _ps_expr(rhs, seen, view(at, collection_vars, local_shapes), dialect)
            chain = chains[at] if scoped else ()
            files = _PsView([file_scopes.get(chain[:n], set()) for n in range(len(chain) + 1)])
            clipboard = any(clipboards.get(chain[:n], False) for n in range(len(chain) + 1))
            tainted = (_ps_fetches(rhs, function_returns)
                       or _ps_reads_remote(rhs, files, clipboard)
                       or any(kind == 'double' and any(_ps_fetches(_ps_tokens(expr, dialect)) for expr in _ps_subexpressions(value)) for kind, value in rhs)
                       or expr_tainted)
            # Writes inside a brace never clear outer taint: an if body may not
            # run and a function or script block may never be called.
            if not scoped or kinds[at] is None:
                owner, shapes, clears = remote_vars, collection_vars, not append and at == start
            elif not chains[at]:
                owner, shapes, clears = remote_vars, collection_vars, False
            else:
                owner = local_vars.setdefault(chains[at][-1], set())
                shapes = local_shapes.setdefault(chains[at][-1], set())
                clears = kinds[at] == 'def' and not append and at == start
            # Collection shape is tracked for clean values too (text appended
            # later joins it); `+=` keeps the old shape.
            # A typed target converts the value: [string]$b = @($a) is a string.
            # Chained targets convert right to left: each target casts the value
            # the target to its right received. A sanitizing cast on one target
            # therefore only clears that target and the ones outside it.
            as_collection, shape = [], expr_collection
            for t, kind in reversed(list(zip(targets, target_shapes))):
                shape = shape if kind is None else kind
                if shape:
                    as_collection.append(t)
            # A target is clean when it or any target to its right sanitizes;
            # one right-to-left pass keeps long `$a=$b=...` chains linear.
            clean, sanitized = set(), False
            for n in range(len(targets) - 1, -1, -1):
                sanitized = sanitized or bool(target_sans[n])
                if sanitized:
                    clean.add(targets[n])
            as_scalar = [t for t in targets if t not in as_collection]
            if as_collection:
                shapes.update(as_collection)
            if clears and as_scalar:
                shapes.difference_update(as_scalar)
            if tainted:
                owner.update(t for t in targets if t not in clean)
            if clears:
                owner.difference_update(t for t in targets if t in clean or not tainted)
        for j in range(start, stop):
            if not j % 16:
                _ps_check_work()
            rv = visible(j)
            name = _ps_name(tokens, j)
            positioned = name in _PS_SINK_NAMES and _ps_position(tokens, j, start)
            embedded = name in ('start-process','saps','ssh','docker','podman','kubectl','su','find','parallel','watch','flock','wmic','schtasks','reg','invoke-wmimethod','invoke-cimmethod') or name.endswith('process]::start')
            if embedded and _ps_position(tokens,j,start):
                for program,program_dialect in _ps_embedded_programs(tokens,j,stop):
                    if detects_powershell_execution(program,depth+1,dialect=program_dialect):
                        return True
            if tokens[j] == ('symbol','&') and j+1<stop and _ps_derives_remote(tokens[j+1:j+2],rv):
                return True
            method_name = _PS_CAST.sub('',tokens[j][1]) if tokens[j][0]=='word' else ''
            scripted = re.fullmatch(r'(\$[\w:]+)\.(addscript|invoke)',method_name)
            if scripted:
                chain=chains[j] if scoped else ()
                key=chain,scripted[1]
                if scripted[2]=='addscript' and j+1<stop:
                    end=ends.get(j+1,stop)
                    body=tokens[j+2:end]
                    if _ps_fetches(body,function_returns) or _ps_derives_remote(body,rv):pending_scripts.add(key)
                elif scripted[2]=='invoke' and key in pending_scripts:
                    return True
            if name in _PS_STDIN_HOST and positioned and _ps_pipe_before(tokens, j, start) and _ps_fetches(tokens[start:j]) and _ps_interpreter_uses_download(tokens, j, stop, name):
                return True
            if name in _PS_CODE_HOST | {'source', '.'} and positioned:
                if next_herestring[j + 1] < stop and any(_ps_remote_program_input(value) for kind, value in tokens[j + 1:stop] if kind in ('string','double')):
                    return True
                operand=j+1
                while operand<stop and (tokens[operand][1].startswith('-') or tokens[operand][1] in ('<','/dev/stdin')):operand+=1
                if operand>j+1 and operand<stop and tokens[operand]==('symbol','(') and _ps_fetches(tokens[operand+1:ends.get(operand,stop)]):
                    return True
            if (name in _PS_HOST or name in _PS_SHELL or name in ('cmd', 'cmd.exe')) and positioned:
                for k in range(j + 1, stop):
                    if not k % 16:
                        _ps_check_work()
                    kind, value = tokens[k]
                    if kind == 'symbol' and value in ('|', ')', '}'):
                        break
                    if kind == 'word' and value in ('-f', '-file'):
                        break
                    if name in _PS_HOST and kind == 'word' and value.lstrip('-/').split(':', 1)[0].lower() in _PS_ENCODED and value.startswith(('-', '/')):
                        return True
                    if kind == 'word' and _ps_code_flag(value, name):
                        if k + 1 < stop and tokens[k + 1][0] == 'word' and _ps_derives_remote(tokens[k + 1:k + 2], rv):
                            return True
                        if k + 1 < stop and (tokens[k + 1][0] in ('string', 'double') or name in _PS_HOST):
                            if name in _PS_CODE_HOST and _ps_remote_program_input(tokens[k + 1][1]):
                                return True
                            program=tokens[k+1][1]
                            if name in _PS_HOST:
                                program=' '.join(value for _,value in tokens[k+1:stop])
                            if detects_powershell_execution(program, depth + 1, dialect='powershell' if name in _PS_HOST else 'shell'):
                                return True
                        break
                if name in _PS_HOST | _PS_SHELL:
                    if j and tokens[j - 1][1] in ('start-process', 'saps'):
                        if any(kind in ('string', 'double') and detects_powershell_execution('pwsh ' + value, depth + 1) for kind, value in tokens[j + 1:stop]):
                            return True
                    if next_herestring[j + 1] < stop:
                        if any(kind in ('string','double') and any(_ps_fetches(_ps_tokens(expr)) for expr in _ps_subexpressions(value)) for kind,value in tokens[j+1:stop]):
                            return True
                        if any(kind in ('string', 'double') and detects_powershell_execution(value, depth + 1, dialect='powershell') for kind, value in tokens[j + 1:stop]):
                            return True
                    if _ps_pipe_before(tokens, j, start) and (name not in _PS_SHELL or _ps_interpreter_uses_download(tokens, j, stop, name)):
                        upstream = tokens[start:j]
                        if any(_ps_name(upstream, at) == 'base64' and _ps_position(upstream, at) for at in range(len(upstream))) and any(value in ('-d','--decode') for _, value in upstream):
                            return True
                        if _ps_fetches(tokens[start:j], function_returns) or _ps_derives_remote(tokens[start:j], rv):
                            return True
                        if any(kind in ('string', 'double') and detects_powershell_execution(value, depth + 1, dialect='powershell') for kind, value in tokens[start:j]):
                            return True
            executor = name in _PS_EXEC | {'eval'} and positioned
            method = tokens[j][0] == 'word' and ((tokens[j][1].startswith('$') and any(member in tokens[j][1] for member in ('.invokescript','.newscriptblock'))) or (tokens[j][1].startswith(('.invokescript', '.addscript')) and j > start and tokens[j - 1][1] == ')') or '[scriptblock]::create' == tokens[j][1])
            if method and (j + 1 >= stop or tokens[j + 1] != ('symbol', '(')):
                continue
            if method and (tokens[j][1].startswith('.addscript') or '.newscriptblock' in tokens[j][1]):
                end = ends.get(j + 1, stop)
                if end + 1 >= stop or not tokens[end + 1][1].startswith('.invoke'):
                    continue
            if method and '[scriptblock]::create' == tokens[j][1]:
                # Creating a block is inert until invoked with & or .Invoke().
                k = j + 1
                end = ends.get(k, stop)
                before = j - 1
                while before >= start and tokens[before][1] == '(':
                    before -= 1
                invoked = before >= start and tokens[before] in (('symbol', '&'), ('word', '.'))
                after = end + 1
                while after < stop and tokens[after][1] == ')':
                    after += 1
                invoked = invoked or (after < stop and tokens[after][1].startswith('.invoke'))
                if not invoked:
                    continue
            if not (executor or method):
                continue
            if _ps_pipe_before(tokens, j, start):
                upstream = tokens[start:j]
                if _ps_fetches(upstream, function_returns) or (executor and _ps_derives_remote(upstream, rv)):
                    return True
                if executor and any(kind in ('string', 'double') and detects_powershell_execution(value, depth + 1, dialect='powershell') for kind, value in upstream):
                    return True
            k = j + 1
            # Execution cmdlet flags can precede the expression.
            while k < stop and tokens[k][0] == 'word' and tokens[k][1].startswith('-'):
                k += 1
                if k < stop and tokens[k][0] == 'word' and not tokens[k][1].startswith('$'):
                    k += 1
            if k < stop and tokens[k] == ('symbol', '('):
                end = ends.get(k, stop)
                # Member calls belong to the operand, e.g. IEX (New-Object
                # Net.WebClient).DownloadString(url), including chained calls.
                after = end + 1
                while after < stop and tokens[after][0] == 'word' and tokens[after][1].startswith('.'):
                    after += 1
                    if after < stop and tokens[after] == ('symbol', '('):
                        after = ends.get(after, stop) + 1
                body = tokens[k:after] if after > end + 1 else tokens[k + 1:end]
            else:
                body = tokens[k:stop]
            if _ps_fetches(body, function_returns) or _ps_derives_remote(body, rv):
                return True
            if (executor or method) and any(value == '$_' for kind, value in body) and (_ps_fetches(tokens[start:j], function_returns) or _ps_derives_remote(tokens[start:j], rv)):
                return True
            if executor and body and body[0][0] == 'double':
                if any(_ps_fetches(_ps_tokens(expr, dialect)) or _ps_derives_remote(_ps_tokens(expr, dialect), rv) for expr in _ps_subexpressions(body[0][1])) or _ps_derives_remote(body[:1], rv):
                    return True
            if executor and body and body[0] == ('word', '@'):
                body = body[1:]
            if executor and body and name == 'eval':
                if detects_powershell_execution(' '.join(value for _, value in body), depth + 1, dialect='shell'):
                    return True
            if executor and body and body[0][0] == 'word' and body[0][1].startswith('('):
                literal_body = _ps_tokens(' '.join(value for _, value in body), 'powershell')
                if _ps_fetches(literal_body, function_returns) or _ps_derives_remote(literal_body, rv):
                    return True
            if executor and body and body[0][0] in ('string', 'double'):
                if detects_powershell_execution(body[0][1], depth + 1, dialect='shell' if name == 'eval' else 'powershell'):
                    return True
        start = stop + 1
    return False


def detect_install_command(command):
    return _ps_guard_inspection(_detect_install_command, command,
        on_error=('inspection_limit', 'inspection failed; split the command and retry'))


def _detect_install_command(command):
    """Match command against install patterns.
    Returns (pattern_type, match_obj) or (None, None)."""
    if not command:
        return None, None
    # Preserve every legacy block before any PowerShell-specific suppression.
    if has_pipe_to_shell(command) and not is_inert_quote_carrier(command):
        return 'pipe_to_shell', None
    try:
        executable = _ps_without_literal_heredocs(command)
        if detects_powershell_execution(executable, heredocs_masked=True):
            return 'pipe_to_shell', None
    except _PsInspectionLimit as limit:
        return 'inspection_limit', str(limit)
    for pattern, ptype in INSTALL_PATTERNS:
        m = pattern.search(command)
        if m:
            return ptype, m
    return None, None


def extract_package_names(pattern_type, match):
    """Extract package names from install command match."""
    if not match:
        return []
    if pattern_type not in ('pip_install', 'npm_install', 'yarn_add', 'gem_install',
                            'cargo_install', 'go_install', 'brew_install', 'openclaw_install',
                            'uv_install', 'bun_install', 'pnpm_install'):
        return []
    raw = match.group(1)
    cleaned = INSTALL_FLAGS.sub('', raw).strip()
    names = [n.strip() for n in cleaned.split() if n.strip() and not n.startswith('-')]
    if pattern_type in ('pip_install', 'uv_install'):
        names = [re.split(r'[>=<!\[\];@]', n)[0] for n in names]
    return names


# npm-family installers pin versions as `name@version`, which the pip/uv strip
# in extract_package_names() deliberately leaves untouched. These are the
# pattern types whose tokens get the split treatment below.
NPM_FAMILY_INSTALLS = ('npm_install', 'yarn_add', 'pnpm_install', 'bun_install')


def split_npm_name_version(token):
    """Split an npm-family install token into (base_name, version).

    The version separator `@` collides with the leading `@` of a scoped name,
    so split on the LAST `@` and only when it is not that scope marker:
      keyv@6.0.0        -> ('keyv', '6.0.0')
      @scope/pkg@1.2.3  -> ('@scope/pkg', '1.2.3')
      @scope/pkg        -> ('@scope/pkg', None)
      keyv              -> ('keyv', None)

    Also resolves the install forms that used to smuggle a malicious package
    past the name/version checks:
      npm alias   local@npm:keyv@6.0.0        -> ('keyv', '6.0.0')
      tarball URL https://reg/keyv/-/keyv-6.0.0.tgz -> ('keyv', '6.0.0')
      git URL     git+https://gh/x/keyv.git   -> ('keyv', None)
    """
    # npm alias: <localname>@npm:<realname>@<version> — resolve to the REAL pkg.
    alias = re.search(r'@npm:(.+)$', token)
    if alias:
        token = alias.group(1)  # realname[@version]

    # URL / git / tarball forms: extract the package name (and version if a
    # tarball encodes one). check_ioc_packages compares whole tokens, so a URL
    # never matches a name — pull the name out so the IOC checks see it.
    if re.match(r'(?i)^(https?://|git\+|git://|ssh://|file:)', token):
        # scoped tarball: .../@scope/name/-/name-1.2.3.tgz -> ('@scope/name', '1.2.3')
        scoped = re.search(
            r'/(@[^/@\s]+/[^/@\s]+)/-/[^/@\s]+-(\d+\.\d+\.\d+[^/\s]*)\.(?:tgz|tar\.gz)$', token)
        if scoped:
            return scoped.group(1), scoped.group(2)
        # unscoped tarball: .../<name>-<version>.tgz
        tgz = re.search(r'/([^/@\s]+)-(\d+\.\d+\.\d+[^/\s]*)\.(?:tgz|tar\.gz)$', token)
        if tgz:
            return tgz.group(1), tgz.group(2)
        # git repo: .../<name>(.git)
        git = re.search(r'/([^/@\s]+?)(?:\.git)?(?:#.*)?$', token)
        if git:
            return git.group(1), None
        return token, None

    idx = token.rfind('@')
    if idx <= 0:
        return token, None
    version = token[idx + 1:]
    return token[:idx], (version or None)


def _semver_tuple(v):
    """Best-effort (major, minor, patch) from a version string. Non-numeric
    trailing segments (prerelease/build) are ignored for comparison."""
    nums = []
    for part in re.split(r'[.\-+]', v.strip()):
        if part.isdigit():
            nums.append(int(part))
        else:
            break
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _spec_could_match(spec, concrete):
    """Could the npm version SPEC (^1.2.0, ~1.2, >=1.0.0, 1.x, 1.2.3, =1.2.3)
    resolve to the concrete COMPROMISED version? The offline gate cannot query
    the registry, so this is deliberately CONSERVATIVE: it returns True whenever
    a range could include the compromised version (better to over-block one
    package than wave a worm through), but False for a clean exact version and
    for dist-tags like `latest`/`next`, which point at the maintainer's current
    — now-fixed — release and must stay installable.
    """
    spec = (spec or '').strip()
    if not spec:
        return False
    if spec.startswith('='):
        spec = spec[1:].strip()
    # A leading `v` on a numeric version (v6.0.0, =v6.0.0) is a VERSION, not a
    # dist-tag — strip it before the dist-tag test below, or `keyv@v6.0.0` (which
    # npm installs as exactly 6.0.0) would be waved through as if it were `latest`.
    spec = re.sub(r'^v(?=\d)', '', spec)
    # dist-tag / non-semver (latest, next, a branch) -> resolves to fixed release
    if re.match(r'^[A-Za-z]', spec):
        return False
    c = _semver_tuple(concrete)
    low = spec.lower().replace('*', 'x')
    # x-ranges: 6.x, 6.*, 6, 6.0.x
    if 'x' in low or re.match(r'^\d+(?:\.\d+)?$', spec):
        parts = low.split('.')
        for i, part in enumerate(parts):
            if part in ('x', ''):
                break
            if not part.isdigit() or (i < len(c) and int(part) != c[i]):
                return False
        return True
    m = re.match(r'^(\^|~|>=|<=|>|<)?\s*v?(\d+(?:\.\d+){0,2}[^\s]*)$', spec)
    if not m:
        return True  # unparseable range -> conservative block
    op = m.group(1) or '='
    t = _semver_tuple(m.group(2))
    if op == '=':
        return c == t
    if op == '^':  # >= t, < next-major (special-cased for 0.x per npm semantics)
        if t[0] > 0:
            return c >= t and c[0] == t[0]
        if t[1] > 0:
            return c >= t and c[0] == 0 and c[1] == t[1]
        return c == t
    if op == '~':  # >= t, < next-minor
        return c >= t and c[0] == t[0] and c[1] == t[1]
    if op == '>=':
        return c >= t
    if op == '>':
        return c > t
    if op == '<=':
        return c <= t
    if op == '<':
        return c < t
    return True


def check_ioc_pinned_versions(pattern_type, package_names, iocs=None):
    """Check npm-family `name@version` tokens against the IOC database.

    Complements check_ioc_packages(), which compares whole tokens against the
    name sets: a pinned token like `rimarf@1.0.0` matches no name, so it used
    to be approved while bare `rimarf` was blocked. Blocks when either the base
    name is a known-malicious package, or the exact pinned version appears in
    the shipped compromised_versions map. Returns a list of description strings.

    `iocs` may be passed pre-loaded so main() loads the IOC set once instead of
    each checker paying the disk+verify cost (the npm path calls both). When
    None, loads on its own (standalone/test use). Fail-open on load failure.
    """
    if pattern_type not in NPM_FAMILY_INSTALLS:
        return []
    if iocs is None:
        try:
            import ioc_manager
            iocs = ioc_manager.get_iocs()
        except (ImportError, AttributeError, KeyError, TypeError):
            return []

    all_malicious = iocs.get('malicious_npm', set()) | iocs.get('malicious_pypi', set())
    compromised_versions = iocs.get('compromised_versions', {})

    blocked = []
    for pkg in package_names:
        base, version = split_npm_name_version(pkg)
        base_lower = base.lower()
        # Check the RESOLVED base name first — for alias (foo@npm:rimarf) and git/URL
        # forms the base is malicious even with no pinned version, and the raw token
        # (which check_ioc_packages compares) never equals the resolved base. Must
        # run before the version-less skip below or these smuggle forms escape.
        if base_lower in all_malicious:
            label = f"{base}@{version}" if version is not None else base
            blocked.append(f"{label} (known-malicious package, any version)")
            continue
        if version is None:
            continue  # bare in-registry names are covered by check_ioc_packages()
        pkg_bad = compromised_versions.get(base_lower, {})
        if not pkg_bad:
            continue
        # exact pin
        if version in pkg_bad:
            blocked.append(f"{base}@{version} (compromised version, campaign: {pkg_bad[version]})")
            continue
        # range / x-range / comparator spec that could resolve to a compromised
        # version (e.g. keyv@^6.0.0 resolving to the bad 6.0.0). Conservative.
        for bad_ver, campaign in pkg_bad.items():
            if _spec_could_match(version, bad_ver):
                blocked.append(
                    f"{base}@{version} (version range may resolve to compromised "
                    f"{bad_ver}, campaign: {campaign})"
                )
                break
    return blocked


def check_ioc_packages(package_names, iocs=None):
    """Check package names against IOC database. Returns list of malicious names.

    Fail-open: if ioc_manager cannot be loaded at all, returns [] (approve).
    When the remote-feed cache is stale or absent, approves but emits a WARNING
    to stderr so the operator knows threat intelligence is degraded.

    `iocs` may be passed pre-loaded so main() loads the IOC set once (the npm
    path runs both checkers); when None it loads on its own.
    """
    if iocs is None:
        try:
            import ioc_manager
            iocs = ioc_manager.get_iocs()
        except (ImportError, AttributeError, KeyError, TypeError):
            return []

    # Warn when operating without a fresh remote IOC feed. We still approve
    # (fail-open) to avoid blocking legitimate work, but the degraded flag
    # tells the operator to run `ioc_manager.py --update` to refresh.
    if iocs.get('_ioc_degraded'):
        if (iocs.get('_ioc_refresh_refused') and iocs.get('_ioc_cache_served')
                and not iocs.get('_ioc_signature_invalid')):
            msg = ("[repo-forensics] WARNING: the latest IOC feed refresh was refused "
                   "(published feed did not verify). Scanning with the last verified "
                   "cached feed plus hardcoded IOCs; it is stale, so recently-discovered "
                   "malicious packages may not be detected. A maintainer must re-sign the "
                   "published feed.")
        elif iocs.get('_ioc_refresh_refused'):
            msg = ("[repo-forensics] WARNING: the latest IOC feed refresh was refused "
                   "(published feed did not verify) and no verified cached feed is "
                   "available. Only hardcoded IOCs are active; recently-discovered "
                   "malicious packages may not be detected. A maintainer must re-sign "
                   "the published feed.")
        else:
            msg = ("[repo-forensics] WARNING: IOC database unavailable, operating without "
                   "threat intelligence. Remote feed cache is absent or stale. Run "
                   "`python3 ioc_manager.py --update` to refresh. Only hardcoded IOCs "
                   "are active; recently-discovered malicious packages may not be detected.")
        print(msg, file=sys.stderr)

    malicious_npm = iocs.get('malicious_npm', set())
    malicious_pypi = iocs.get('malicious_pypi', set())
    all_malicious = malicious_npm | malicious_pypi

    blocked = []
    for pkg in package_names:
        if pkg.lower() in all_malicious:
            blocked.append(pkg)
    return blocked


# --- Registry risk (the `ask` tier) -----------------------------------------
#
# An install command pointed at a plaintext-HTTP index, or at a registry host
# that is not the ecosystem's canonical one, is the setup step for dependency
# confusion and for registry MITM. It is NOT block-worthy on its own: corporate
# mirrors and internal indexes are legitimate and common, which is exactly why
# forensics_core grades the file-based version of this signal MEDIUM rather
# than HIGH. On an adapter that has a third verdict (Cursor's `ask`) this is
# the signal that tier exists for: surface it to the human, do not hard-stop
# the agent. On the Claude shape, which has no `ask`, it degrades to an
# approve plus a stderr note so the operator still sees it.
_INDEX_FLAG = re.compile(
    r'--(?:index-url|extra-index-url|registry|repository|default-index)'
    r'(?:[=\s]+)(["\']?)([a-zA-Z][a-zA-Z0-9+.-]*://[^\s"\';|&]+)\1',
    re.IGNORECASE,
)

# Canonical first-party registry hosts per ecosystem. A redirect away from
# these is what makes the flag interesting.
CANONICAL_REGISTRY_HOSTS = frozenset({
    'pypi.org', 'www.pypi.org', 'files.pythonhosted.org', 'pypi.python.org',
    'registry.npmjs.org', 'registry.yarnpkg.com', 'npm.pkg.github.com',
    'rubygems.org', 'index.rubygems.org',
    'crates.io', 'static.crates.io', 'index.crates.io',
    'proxy.golang.org',
})


def _registry_host(url):
    """Host portion of a registry URL, lowercased, port and creds stripped."""
    rest = url.split('://', 1)[1] if '://' in url else url
    authority = re.split(r'[/?#]', rest, 1)[0]
    if '@' in authority:
        authority = authority.rsplit('@', 1)[1]
    if authority.startswith('['):  # IPv6 literal
        return authority.split(']', 1)[0].lstrip('[').lower()
    return authority.split(':', 1)[0].lower()


def detect_registry_risk(command):
    """Return a human-readable reason when an install command redirects its
    package index, else None. Never blocks — the caller maps this to `ask`."""
    if not command:
        return None
    for match in _INDEX_FLAG.finditer(command):
        url = match.group(2)
        scheme = url.split('://', 1)[0].lower()
        host = _registry_host(url)
        if scheme == 'http':
            return (f"package index redirected to a plaintext HTTP endpoint "
                    f"({url}) — credentials and package payloads are readable "
                    f"and rewritable in transit")
        if scheme in ('https', 'ftp', 'ftps') and host not in CANONICAL_REGISTRY_HOSTS:
            return (f"package index redirected to the non-canonical host "
                    f"'{host}' — legitimate for an internal mirror, and also "
                    f"how dependency-confusion attacks are staged")
    return None


def output_block(reason):
    """Output JSON that tells the agent to block the command.

    Claude Code reads the JSON decision on stdout; Kimi Code blocks on exit
    code 2 and surfaces stderr as the reason. Emit both so either host shows
    the operator why the command was blocked."""
    result = {
        "decision": "block",
        "reason": reason
    }
    print(json.dumps(result))
    print(reason, file=sys.stderr)
    sys.exit(2)


def output_approve():
    """Output empty JSON — command proceeds normally (Claude shape)."""
    print('{}')
    sys.exit(0)


BLOCK_PIPE_TO_SHELL = (
    "[repo-forensics] BLOCKED: Command executes downloaded content or uses "
    "an opaque PowerShell EncodedCommand. This bypasses package manager "
    "security checks and can execute arbitrary code."
)
BLOCK_LEGACY_PIPE = (
    '[repo-forensics] BLOCKED: Command matches the legacy downloader-to-shell '
    'rule. This rule also covers shell syntax checks and literal examples.'
)


def _block_packages_reason(pkg_list):
    return (
        f"[repo-forensics] BLOCKED: Known malicious package(s) detected: "
        f"{pkg_list}. These packages match the IOC database and should NOT "
        f"be installed. Remove them from the command and try again."
    )


def decide(command):
    return _ps_guard_inspection(_decide, command,
        on_error=(hook_adapter.DENY, '[repo-forensics] Inspection failed; split the command and retry.'))


def _decide(command):
    """Run the detection gate on a shell command string.

    Returns (permission, message) with permission in {allow, ask, deny}. This
    is the ONE detection path; every adapter reaches the gate through here, so
    a verdict can never diverge between wires (PRD v3 G3/N1).
    """
    if not command:
        return hook_adapter.ALLOW, ""

    # Detect install/update pattern (also catches pipe-to-shell)
    pattern_type, match = detect_install_command(command)

    if pattern_type == 'inspection_limit':
        return hook_adapter.DENY, '[repo-forensics] BLOCKED: ' + match + '; command could not be fully inspected.'

    # Pipe-to-shell: instant block
    if pattern_type == 'pipe_to_shell':
        if has_pipe_to_shell(command) and not is_inert_quote_carrier(command):
            return hook_adapter.DENY, BLOCK_LEGACY_PIPE
        return hook_adapter.DENY, BLOCK_PIPE_TO_SHELL

    if not pattern_type:
        return hook_adapter.ALLOW, ""

    # Extract package names and check IOC
    package_names = extract_package_names(pattern_type, match)
    if not package_names:
        risk = detect_registry_risk(command)
        return (hook_adapter.ASK, _registry_ask_reason(risk)) if risk else (hook_adapter.ALLOW, "")

    # Load the IOC set ONCE and pass it to both checkers. The npm-family path
    # runs both check_ioc_packages() and check_ioc_pinned_versions(); without
    # sharing, get_iocs() (disk read + Ed25519 verify + set rebuild) ran twice.
    shared_iocs = None
    try:
        import ioc_manager
        shared_iocs = ioc_manager.get_iocs()
    except Exception:
        # Any failure loading IOCs must fail OPEN cleanly (the checkers re-load and
        # also fail open). Catch broadly so an unexpected error never crashes the
        # hook without emitting the approve JSON the PreToolUse contract requires.
        shared_iocs = None

    blocked_packages = check_ioc_packages(package_names, iocs=shared_iocs)
    if blocked_packages:
        return hook_adapter.DENY, _block_packages_reason(', '.join(blocked_packages))

    # Version-pinned npm-family tokens (`name@version`) never match the name
    # sets above, so re-check them by base name and exact pinned version.
    blocked_pinned = check_ioc_pinned_versions(pattern_type, package_names, iocs=shared_iocs)
    if blocked_pinned:
        return hook_adapter.DENY, _block_packages_reason(', '.join(blocked_pinned))

    # No IOC match. A redirected package index is the one remaining signal
    # worth a human's attention without stopping the agent.
    risk = detect_registry_risk(command)
    if risk:
        return hook_adapter.ASK, _registry_ask_reason(risk)

    return hook_adapter.ALLOW, ""


def _registry_ask_reason(risk):
    return (f"[repo-forensics] REVIEW: {risk}. Approve only if you recognise "
            f"this index as your own.")


def _main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    adapter, adapter_error = hook_adapter.normalize_adapter(
        hook_adapter.adapter_from_argv(argv))
    if adapter_error:
        # A typo in our own installed hook command must not brick every shell
        # command, so this warns and runs the fail-open adapter. Anyone who can
        # edit the hook command line could equally have deleted the hook.
        print(f"[repo-forensics] WARNING: {adapter_error}; falling back to "
              f"'{hook_adapter.ADAPTER_CLAUDE}'", file=sys.stderr)

    fail_closed = adapter in hook_adapter.FAIL_CLOSED_ADAPTERS

    def emit(permission, message="", note=None):
        sys.exit(hook_adapter.emit_verdict(
            adapter, permission, user_message=message, agent_message=message,
            stderr_note=note))

    # (1) Blanket disable. Documented as the last resort precisely because it
    # also switches off the fail-closed denials below.
    switch = hook_adapter.kill_switch_state()
    if switch == "unsafe":
        emit(hook_adapter.ALLOW, "", note=(
            f"[repo-forensics] WARNING: {hook_adapter.KILL_SWITCH_ENV}="
            f"{hook_adapter.KILL_SWITCH_UNSAFE} — the pre-execution gate is FULLY "
            f"disabled, including tamper and schema-drift detection. Nothing is "
            f"being checked before this command runs."))

    # (2) Install-manifest integrity (R8). Checked BEFORE the allow branch and
    # before the ordinary kill switch: a scanner that the manifest says should
    # be here but is not is tampering, not a missing optional feature.
    root = hook_adapter.plugin_root()
    integrity, integrity_detail = hook_adapter.check_install_integrity(root)
    if integrity == hook_adapter.INTEGRITY_TAMPER:
        note = (f"[repo-forensics] TAMPER: {integrity_detail}. Refusing to "
                f"approve while the install is in an inconsistent state; "
                f"reinstall repo-forensics or unset {hook_adapter.PLUGIN_ROOT_ENV}.")
        if fail_closed:
            emit(hook_adapter.DENY, note, note=note)
        # Fail-open adapters keep their shipped behaviour (a PreToolUse hook
        # that starts denying on upgrade would be a breaking change), but the
        # operator is told loudly.
        print(note, file=sys.stderr)

    # (3) Envelope. Drift denies on a failClosed wire, approves on the others.
    raw = hook_adapter.read_stdin(limit=hook_adapter.MAX_STDIN_BYTES + 1)
    if len(raw) > hook_adapter.MAX_STDIN_BYTES:
        note = ("[repo-forensics] Hook input exceeds the inspection limit; "
                "refusing to approve a command that could not be fully read. Split the command and retry.")
        emit(hook_adapter.DENY, note, note=note)
    request = hook_adapter.parse_request(adapter, raw)
    if request.drift:
        note = (f"[repo-forensics] SCHEMA DRIFT: {request.drift}. A hook that "
                f"cannot read its own input cannot vouch for the command.")
        if fail_closed:
            emit(hook_adapter.DENY, note, note=note)
        emit(hook_adapter.ALLOW, "")

    # (4) Genuinely not installed at this root: allow, but never silently.
    if integrity == hook_adapter.INTEGRITY_UNCLAIMED:
        emit(hook_adapter.ALLOW, "", note=(
            f"[repo-forensics] WARNING: {integrity_detail}. The pre-execution "
            f"gate is NOT protecting this command."))

    # (5) Ordinary kill switch: detection off, integrity still enforced.
    if switch == "detection":
        emit(hook_adapter.ALLOW, "", note=(
            f"[repo-forensics] WARNING: {hook_adapter.KILL_SWITCH_ENV}="
            f"{hook_adapter.KILL_SWITCH_OFF} — malicious-package and "
            f"pipe-to-shell detection is disabled for this command. "
            f"Precedence: {hook_adapter.PRECEDENCE_DOC}."))

    # (6) Detection.
    permission, message = decide(request.command)
    emit(permission, message)


def main(argv=None):
    result = _ps_guard_inspection(_main, argv, hard_stop=False,
        on_error=(hook_adapter.DENY, '[repo-forensics] Inspection failed; split the command and retry.'))
    if result is not None:
        args = list(sys.argv[1:]) if argv is None else list(argv)
        adapter, _ = hook_adapter.normalize_adapter(hook_adapter.adapter_from_argv(args))
        permission, message = result
        sys.exit(hook_adapter.emit_verdict(adapter, permission, user_message=message, agent_message=message))


if __name__ == '__main__':
    # This process exists only for the check: charge interpreter start-up
    # and envelope parsing to the same work budget.
    _PS_WORK_START.set(0.0)
    main()
