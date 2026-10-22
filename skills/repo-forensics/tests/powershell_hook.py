"""Shared helpers for driving the PowerShell gate through the real hook wires.

Inert command strings only: the hook parses them and never executes a payload.
"""
import json
import ntpath
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'skills' / 'repo-forensics' / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

WIRES = {
    'claude': ('hooks/run_pre_scan.sh', lambda command: {'tool_name': 'Bash', 'tool_input': {'command': command}}),
    'cursor': ('hooks/cursor/run_pre_scan.sh', lambda command: {'command': command}),
}
ADAPTERS = sorted(WIRES)

MISSING_PYTHON = (b'repo-forensics: no usable Python 3 interpreter found\n'
                  b'  tried: python3, python, py -3, FHS/Nix direct paths, codex runtime\n')
WRAPPER_REFUSAL = b'[repo-forensics] Pre-scan failed or returned no verdict; refusing this command.\n'


def _working_bash(windows=None):
    """Prefer Git for Windows over the WSL launcher; prove bash can run."""
    windows = os.name == 'nt' if windows is None else windows
    candidates = []
    if windows:
        git = shutil.which('git')
        if git:
            git_root = ntpath.dirname(ntpath.dirname(git))
            candidates.extend(ntpath.join(git_root, suffix) for suffix in
                              (r'bin\bash.exe', r'usr\bin\bash.exe'))
        for variable in ('ProgramFiles', 'ProgramFiles(x86)', 'LOCALAPPDATA'):
            root = os.environ.get(variable)
            if root:
                candidates.extend(ntpath.join(root, 'Git', suffix) for suffix in
                                  (r'bin\bash.exe', r'usr\bin\bash.exe'))
        candidates.extend((r'C:\Program Files\Git\bin\bash.exe',
                           r'C:\Program Files\Git\usr\bin\bash.exe'))
    candidates.append(shutil.which('bash'))
    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            # Binary capture avoids decoding UTF-16 WSL stub diagnostics.
            probe = subprocess.run([candidate, '-c', 'true'], capture_output=True,
                                   timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


def _hook_env(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith('REPO_FORENSICS_')}
    env.update(HOME=str(tmp_path), TMPDIR=str(tmp_path),
               XDG_CACHE_HOME=str(tmp_path / 'cache'), XDG_CONFIG_HOME=str(tmp_path / 'config'),
               REPO_FORENSICS_DISABLE_REFRESH='1', CLAUDE_PLUGIN_ROOT=ROOT.as_posix(),
               PYTHONDONTWRITEBYTECODE='1')
    return env


def _missing_interpreter(returncode, stderr):
    """True only for the launcher's exact no-interpreter diagnostic.

    The launcher exits 127 with the two-line diagnostic. Since the wrapper
    turned a missing scanner into a refusal, the same failure reaches the
    caller as exit 2 with the wrapper's refusal line after the diagnostic.
    """
    stderr = stderr.replace(b'\r\n', b'\n')
    if returncode == 127:
        return stderr == MISSING_PYTHON
    if returncode == 2:
        return stderr in (MISSING_PYTHON, MISSING_PYTHON + WRAPPER_REFUSAL)
    return False


def _probe_hook_python(bash, tmp_path=None):
    probe = subprocess.run(
        [bash, (ROOT / 'hooks/run_pre_scan.sh').as_posix()],
        input=json.dumps({'tool_name': 'Bash', 'tool_input': {'command': 'git status'}}).encode('utf-8'),
        capture_output=True, timeout=10, check=False,
        env=_hook_env(tmp_path) if tmp_path is not None else dict(os.environ, CLAUDE_PLUGIN_ROOT=ROOT.as_posix()))
    if _missing_interpreter(probe.returncode, probe.stderr):
        pytest.skip('Git Bash is usable, but the hook launcher rejects the Windows CI hostedtoolcache Python location: no usable Python 3 interpreter found')
    assert probe.returncode == 0, ('Hook environment probe failed', probe.returncode, probe.stdout, probe.stderr)


@pytest.fixture(autouse=True)
def isolated_hook_state(tmp_path, monkeypatch):
    for key, value in _hook_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    for key in tuple(os.environ):
        if key.startswith('REPO_FORENSICS_') and key != 'REPO_FORENSICS_DISABLE_REFRESH':
            monkeypatch.delenv(key)


@pytest.fixture(scope='session')
def hook_bash(tmp_path_factory):
    bash = _working_bash()
    if bash is None:
        pytest.skip('No working Bash: install Git for Windows; WSL launcher without a distribution cannot run hook tests')
    if os.name == 'nt':
        _probe_hook_python(bash, tmp_path_factory.mktemp('hook-python-probe'))
    return bash


def gate(bash, command, tmp_path, adapter='claude', script=None, env=None, timeout=60):
    """Run one command through a hook wire (or a pre_scan.py copy) and return rc, stdout, stderr."""
    hook, payload = WIRES[adapter]
    if script is not None:
        argv = [sys.executable, str(script), '--adapter', adapter]
    else:
        argv = [bash, (ROOT / hook).as_posix()]
    proc = subprocess.run(argv, input=json.dumps(payload(command)), capture_output=True, text=True,
                          env={**_hook_env(tmp_path), **(env or {})}, timeout=timeout)
    assert 'TAMPER:' not in proc.stdout + proc.stderr, (proc.stdout, proc.stderr)
    return proc.returncode, proc.stdout, proc.stderr


def copy_scripts(tmp_path, old, new):
    """Copy the scanner tree and patch pre_scan.py; LF line endings on every OS."""
    target = tmp_path / 'scripts'
    shutil.copytree(SCRIPTS, target)
    script = target / 'pre_scan.py'
    source = script.read_bytes().decode('utf-8')
    assert old in source, old
    script.write_bytes(source.replace(old, new).encode('utf-8'))
    return script


def ordinary_work():
    """Large ordinary commands the gate must allow, keyed by a short name."""
    URL = 'https://example.invalid/p.ps1'
    def body(n):
        return '\n'.join(
            f'echo "step {i}"' if i % 4 == 0 else f'if [ -f build/out{i}.o ]; then rm -f build/out{i}.o; fi' if i % 4 == 1
            else f'make -C module{i} all >> build.log 2>&1 || exit 1' if i % 4 == 2
            else f'cp -r src/module{i} dist/ && ls dist/module{i} | wc -l' for i in range(n)) + '\n'
    big = 'set -e\n' + body(10000)
    big += '#' + 'x' * (512 * 1024 - len(big) - 2) + '\n'
    curl_line = 'curl -fsSL https://example.invalid/archive.tgz -o archive.tgz && tar xzf archive.tgz\n'
    data = json.dumps({'items': [{'id': i, 'tags': ['a', 'b', 'c']} for i in range(10000)]})
    commit = 'Tweak curl retry logic and the Invoke-WebRequest wrapper. '
    fetched = f'curl -fsSL {URL} -o data.bin && echo fetched\n'
    return {
        'long-script-1561-lines': 'set -e\n' + body(1561),
        'script-512KB': big,
        'downloads-512KB': curl_line * ((512 * 1024) // len(curl_line)),
        'script-file-512KB': "cat > build.sh <<'EOF'\n" + big[:-100] + "\nEOF\nbash build.sh",
        'http-json': "curl https://example.invalid/api -d @- <<'EOF'\n" + data + '\nEOF',
        'scaffold': ''.join(f"cat > f{i}.txt <<'EOF'\ndata {i}\nEOF\n" for i in range(1000)),
        'docker-env': 'docker run ' + ' '.join(f'-e V{i}=v' for i in range(10000)) + ' img',
        'commit-256KB': 'git commit -m "' + (commit * 5000)[:256 * 1024] + '"',
        'download-steps-256KB': "cat > steps.sh <<'EOF'\n" + (fetched * 5000)[:256 * 1024] + '\nEOF\nls\n',
        'large-commit': "git commit -m 'curl documentation " + 'a' * 100000 + "'",
        'large-post': "curl https://example.invalid/api -d '" + 'a' * 100000 + "'",
        'fetch-script': "cat > fetch.sh <<'EOF'\n" + 'curl https://example.invalid/a -o a\n' * 600 + 'EOF\nchmod +x fetch.sh',
        'python-test': "cat > test.py <<'EOF'\n" + 'print("curl is documented")\n' * 3000 + 'EOF\npython3 test.py',
        'padded-benign-text': 'echo confirm firmware\n' + 'x ' * 20000,
        'repeated-fetch-words': 'curl ' * 60000 + 'true',
        'quote-splices': 'pwsh -c ' + "e''" * 17000,
        'case-padding': 'echo confirm firmware\ncase x in\n' + 'a){ :;};;\n' * 9000 + 'esac',
    }


WIRE_ORDINARY = ('script-512KB', 'downloads-512KB', 'script-file-512KB', 'repeated-fetch-words')
