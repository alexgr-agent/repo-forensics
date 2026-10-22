"""Compromised PyPI pins must be caught by the install gate and the file scan.

Regression for the LiteLLM 1.107.0 PyPI compromise (October 2026): the wheel
carries cook.pth / sitecustomize.py startup hooks that are absent from the git
tag, so the only reliable pre-execution signal is the pinned version itself.
Before this, pip/uv version specifiers were discarded by the install gate, the
compromised-version map was only consulted for npm-family installs, and
requirements-style files never fed their pins to the compromised-version check.
"""

import json
import os
import sys

import pytest

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts'))
sys.path.insert(0, SCRIPTS_DIR)

import auto_scan  # noqa: E402
import hook_adapter  # noqa: E402
import ioc_manager  # noqa: E402
import pre_scan  # noqa: E402
import pypi_pins  # noqa: E402
import scan_dependencies as scanner  # noqa: E402

BAD = {'1.107.0': 'c-oct', '1.82.8': 'c-mar'}
DB = {'litellm': BAD}


@pytest.fixture
def iocs():
    return ioc_manager.get_iocs()


# --- shipped data -----------------------------------------------------------

def test_shipped_pypi_map_has_the_october_release(iocs):
    pypi = iocs['compromised_versions_pypi']
    assert pypi['litellm']['1.107.0'] == 'litellm_pypi_oct_2026'
    assert pypi['litellm']['1.82.8']  # March campaign stays


def test_pypi_map_excludes_other_ecosystems(iocs):
    pypi = iocs['compromised_versions_pypi']
    assert 'axios' not in pypi and 'chalk' not in pypi        # npm
    assert 'laravel-lang/lang' not in pypi                    # composer


def test_pypi_map_names_are_pep503_normalised(tmp_path):
    raw = {'campaigns': {'x': {'ecosystem': 'pypi',
                               'packages': {'Foo_Bar.baz': ['1.0.0'], 'wild': ['*']}}}}
    got = ioc_manager._pypi_version_map(raw)
    assert got == {'foo-bar-baz': {'1.0.0': 'x'}}
    assert pypi_pins.normalize_name('Foo_Bar.baz') == 'foo-bar-baz'


def test_exfil_domain_is_in_hardcoded_iocs(iocs):
    assert 'litellm.dev' in iocs['malicious_domains']
    assert 'cook.pth' in iocs['malicious_pth_files']


# --- pypi_pins parsing ------------------------------------------------------

@pytest.mark.parametrize('args', [
    'litellm==1.107.0',
    '"litellm==1.107.0"',
    "'LiteLLM==1.107.0'",
    'litellm == 1.107.0',
    'litellm==1.107',                 # PEP 440 pads zeros
    'litellm==1.107.0.0',
    'litellm==v1.107.0',
    'litellm==0!1.107.0',
    'litellm===1.107.0',
    'litellm==1.107.*',
    'litellm==1.*',
    'litellm[proxy]==1.107.0',
    'litellm[proxy,extra] == 1.107.0',
    'Lite_LLM==1.107.0',              # not litellm, see below
    '--upgrade litellm==1.107.0',
    '-q --no-cache-dir litellm==1.107.0 requests',
    'requests litellm==1.107.0',
    'litellm==1.107.0 && echo done',
    'requests && pip install litellm==1.107.0',
    'requests; pip3 install -q "litellm==1.107.0"',
    'litellm==1.107.0; python_version>"3.8"',
    'litellm==1.107.0 --hash=sha256:abc',
    'litellm @ https://files.pythonhosted.org/packages/x/litellm-1.107.0-py3-none-any.whl',
    'litellm@https://files.pythonhosted.org/x/litellm-1.107.0-py3-none-any.whl',
    'https://files.pythonhosted.org/x/litellm-1.107.0.tar.gz',
    'https://files.pythonhosted.org/x/litellm-1.107.0-py3-none-any.whl#sha256=abc',
])
def test_blocked_spellings(args):
    got = pypi_pins.blocked_by(pypi_pins.parse_install_args(args), DB)
    if args.startswith('Lite_LLM'):
        assert got == []  # lite-llm is a different distribution
    else:
        assert got and 'litellm' in got[0] and '1.107.0' in got[0]


@pytest.mark.parametrize('args', [
    'litellm==1.108.0',
    'litellm==1.107.1',
    'litellm==1.107.0.post1',
    'litellm==1.107.0rc1',
    'litellm==1.107.0+local',
    'litellm==1.10.7',
    'litellm==1.17.0',
    'litellm>=1.107.0',
    'litellm~=1.107.0',
    'litellm',
    'litellm[proxy]',
    '"litellm>=1.100"',
    'litellm!=1.107.0',
    'litellm==1.*.0',
    'litellm==',
    '-r litellm==1.107.0',            # value of -r is a file, not a requirement
    '-c litellm==1.107.0',
    'requests==1.107.0',
    '',
])
def test_not_blocked_spellings(args):
    assert pypi_pins.blocked_by(pypi_pins.parse_install_args(args), DB) == []


@pytest.mark.parametrize('arg', [
    r'C:\Users\a\dl\litellm-1.107.0-py3-none-any.whl',
    r'"C:\Program Files\x\litellm-1.107.0-py3-none-any.whl"',
    './litellm-1.107.0-py3-none-any.whl',
    'dist/litellm-1.107.0.tar.gz',
    'litellm-1.107.0-py3-none-any.whl',
    'file:///tmp/litellm-1.107.0-py3-none-any.whl',
])
def test_local_artifact_paths(arg):
    assert pypi_pins.blocked_by(pypi_pins.parse_install_args(arg), DB)


@pytest.mark.parametrize('payload', ['1' * 30000 + '!', '.'.join(['1'] * 15000) + '!',
                                     '1.' * 30000, 'litellm==' + '1.0' * 10000 + 'x'],
                         ids=['digits', 'dotted', 'trailing-dots', 'long-pin'])
def test_parser_is_linear_time(payload):
    import time
    t0 = time.time()
    pypi_pins.parse_install_args('pip install ' + payload)
    pypi_pins.spec_hits('==' + payload, BAD)
    pypi_pins.parse_requirement(payload)
    assert time.time() - t0 < 2


def test_parser_never_raises_on_hostile_input():
    for raw in ['"', "'", '\\', '==', '@', '@@@', '[', 'a' * 100000, '\x00==1', '😀==1',
                'litellm==' + '9' * 5000, '=' * 1000, ' '.join(['x'] * 5000)]:
        pypi_pins.parse_install_args(raw)
        pypi_pins.spec_hits(raw, BAD)
        pypi_pins.parse_requirement(raw)
    assert pypi_pins.parse_install_args(None) == []
    assert pypi_pins.spec_hits(None, BAD) == []
    assert pypi_pins.normalize_name(None) == ''


# --- the blocking gate ------------------------------------------------------

@pytest.mark.parametrize('cmd', [
    'pip install litellm==1.107.0',
    'pip3 install litellm==1.107.0',
    'python -m pip install litellm==1.107.0',
    'pip install --upgrade "litellm==1.107.0"',
    'uv pip install litellm==1.107.0',
    'uv add litellm==1.107.0',
    'uv add "litellm[proxy]==1.107.0"',
    'pip install requests litellm==1.107.0',
    'pip install litellm==1.82.8',
    'pip install litellm==1.107.*',
    'pip install requests && pip install litellm==1.107.0',
    'cd app; uv pip install --system litellm==1.107.0',
    'pip install -r requirements.txt litellm==1.107.0',
])
def test_gate_denies_compromised_pin(cmd):
    perm, msg = pre_scan.decide(cmd)
    assert perm == hook_adapter.DENY
    assert 'litellm' in msg


@pytest.mark.parametrize('cmd', [
    'pip install litellm==1.108.0',
    'pip install litellm',
    'pip install litellm>=1.0',
    'pip install requests==2.31.0',
    'uv add litellm',
    'pip install -r requirements.txt',
])
def test_gate_allows_everything_else(cmd):
    perm, _ = pre_scan.decide(cmd)
    assert perm == hook_adapter.ALLOW


def test_gate_fails_open_when_iocs_unloadable(monkeypatch):
    def boom(*a, **k):
        raise ImportError('no iocs')
    monkeypatch.setattr(ioc_manager, 'get_iocs', boom)
    perm, _ = pre_scan.decide('pip install litellm==1.107.0')
    assert perm == hook_adapter.ALLOW


def test_gate_still_blocks_quoted_known_malicious_name():
    # the quote used to ride along in the name and hide it from the name check
    perm, _ = pre_scan.decide('pip install "anthopic==1.0"')
    assert perm == hook_adapter.DENY


def test_npm_pinned_gate_unchanged():
    perm, _ = pre_scan.decide('npm install chalk@5.6.1')
    assert perm == hook_adapter.DENY


def test_hook_end_to_end_blocks_with_exit_2(tmp_path):
    import subprocess
    payload = json.dumps({'tool_name': 'Bash',
                          'tool_input': {'command': 'pip install litellm==1.107.0'}})
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS_DIR, 'pre_scan.py')],
                       input=payload, capture_output=True, text=True, timeout=30,
                       env={**os.environ, 'HOME': str(tmp_path), 'XDG_CACHE_HOME': str(tmp_path)})
    assert r.returncode == 2
    assert json.loads(r.stdout.strip().splitlines()[-1])['decision'] == 'block'


# --- post-install report ----------------------------------------------------

def test_auto_scan_reports_pin():
    pt, m = auto_scan.detect_install_command('pip install litellm==1.107.0')
    got = auto_scan.check_pypi_pinned_versions(pt, m)
    assert len(got) == 1 and got[0]['severity'] == 'critical'
    assert '1.107.0' in got[0]['title']


def test_auto_scan_ignores_clean_pin_and_npm():
    pt, m = auto_scan.detect_install_command('pip install litellm==1.108.0')
    assert auto_scan.check_pypi_pinned_versions(pt, m) == []
    pt, m = auto_scan.detect_install_command('npm install litellm@1.107.0')
    assert auto_scan.check_pypi_pinned_versions(pt, m) == []


# --- file scan --------------------------------------------------------------

def _titles(findings):
    return [f.title for f in findings if f.category == 'supply-chain']


def test_requirements_pin_is_flagged(tmp_path):
    f = tmp_path / 'requirements.txt'
    f.write_text('requests==2.31.0\nLiteLLM[proxy] == 1.107.0 --hash=sha256:aa  # pinned\n')
    got = scanner.scan_python_deps(str(f), 'requirements.txt')
    hits = [x for x in got if x.title == 'Compromised Package Version: litellm==1.107.0']
    assert len(hits) == 1
    assert hits[0].severity == 'critical' and hits[0].line == 2


@pytest.mark.parametrize('name', ['requirements.txt', 'requirements-dev.txt',
                                  'requirements-test.txt', 'constraints.txt'])
def test_all_requirement_file_names(tmp_path, name):
    f = tmp_path / name
    f.write_text('litellm==1.82.8\n')
    assert any('litellm==1.82.8' in t for t in _titles(scanner.scan_python_deps(str(f), name)))


def test_requirements_clean_and_ranges_not_flagged(tmp_path):
    f = tmp_path / 'requirements.txt'
    f.write_text('litellm==1.108.0\nlitellm>=1.0\nlitellm\n# litellm==1.107.0\n-r other.txt\n')
    assert not any('Compromised' in t for t in _titles(scanner.scan_python_deps(str(f), 'r')))


def test_pyproject_pin_is_flagged(tmp_path):
    f = tmp_path / 'pyproject.toml'
    f.write_text('[project]\nname = "app"\ndependencies = [\n  "litellm == 1.107.0",\n  "requests",\n]\n')
    assert any('litellm==1.107.0' in t for t in _titles(scanner.scan_python_deps(str(f), 'p')))


def test_pyproject_range_not_flagged(tmp_path):
    f = tmp_path / 'pyproject.toml'
    f.write_text('[project]\ndependencies = ["litellm>=1.107.0"]\n')
    assert not any('Compromised' in t for t in _titles(scanner.scan_python_deps(str(f), 'p')))


def test_pipfile_pins_are_flagged(tmp_path):
    f = tmp_path / 'Pipfile'
    f.write_text('[packages]\nlitellm = "==1.107.0"\nxinference = {version = "==2.6.1", extras = ["a"]}\n'
                 'requests = "*"\n')
    t = _titles(scanner.scan_python_deps(str(f), 'Pipfile'))
    assert any('litellm==1.107.0' in x for x in t)
    assert any('xinference==2.6.1' in x for x in t)


def test_file_scan_does_not_cross_ecosystems(tmp_path):
    # chalk 5.6.1 is an npm compromise; a PyPI "chalk==5.6.1" is not that package
    f = tmp_path / 'requirements.txt'
    f.write_text('chalk==5.6.1\naxios==1.14.1\n')
    assert not any('Compromised' in t for t in _titles(scanner.scan_python_deps(str(f), 'r')))


def test_offline_fallback_knows_the_october_release():
    assert '1.107.0' in scanner.COMPROMISED_PACKAGE_VERSIONS['litellm']
    db = {}
    for v in scanner.COMPROMISED_PACKAGE_VERSIONS['litellm']:
        db[v] = 'local-fallback'
    assert pypi_pins.spec_hits('==1.107.0', db)


def test_full_directory_scan_flags_requirements(tmp_path):
    (tmp_path / 'requirements.txt').write_text('litellm==1.107.0\n')
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS_DIR, 'scan_dependencies.py'),
                        str(tmp_path), '--format', 'json', '--offline', '--skip-freshness'],
                       capture_output=True, text=True, timeout=60)
    data = json.loads(r.stdout)
    items = data['findings'] if isinstance(data, dict) else data
    assert any(i['title'] == 'Compromised Package Version: litellm==1.107.0' for i in items)


# --- install-command shapes the gate used to miss ---------------------------

@pytest.mark.parametrize('cmd', [
    'pip3.12 install litellm==1.107.0',
    'pip3.9 install --user litellm==1.107.0',
    'pip -q install litellm==1.107.0',
    'python -m pip --disable-pip-version-check install litellm==1.107.0',
    'pip --proxy http://proxy:3128 install litellm==1.107.0',
])
def test_gate_sees_pip_variants(cmd):
    assert pre_scan.decide(cmd)[0] == hook_adapter.DENY
    assert auto_scan.detect_install_command(cmd)[0] == 'pip_install'


@pytest.mark.parametrize('cmd', ['pip --version', 'pip freeze', 'pip list install',
                                 'pip3.12 install requests', 'echo pip'])
def test_gate_does_not_overmatch_pip(cmd):
    assert pre_scan.decide(cmd)[0] == hook_adapter.ALLOW


def test_install_pattern_is_linear_time():
    import time
    for c in ['pip ' + '-a ' * 30000 + 'x', 'pip ' + '--x y ' * 20000, 'pip ' + '-' * 50000 + ' install']:
        t0 = time.time()
        pre_scan.detect_install_command(c)
        auto_scan.detect_install_command(c)
        assert time.time() - t0 < 2


# --- requirements-style files outside the four standard names --------------

@pytest.mark.parametrize('rel', ['requirements-prod.txt', 'dev-requirements.txt',
                                 'requirements.in', 'constraints-3.12.txt',
                                 'requirements/base.txt', 'requirements/prod.in',
                                 'requirements_all.txt'])
def test_extra_requirements_names_are_scanned(tmp_path, rel):
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text('litellm==1.107.0\n')
    assert scanner.is_extra_requirements_file(str(f))
    got = scanner.scan_pypi_pins_only(str(f), rel)
    assert [x.title for x in got] == ['Compromised Package Version: litellm==1.107.0']


@pytest.mark.parametrize('rel', ['requirements.txt', 'README.txt', 'notes.txt',
                                 'package.json', 'src/requirements_check.py',
                                 'docs/requirementsx.txt'])
def test_unrelated_names_do_not_take_the_extra_path(tmp_path, rel):
    assert not scanner.is_extra_requirements_file(str(tmp_path / rel))


def test_extra_files_get_no_unrelated_noise(tmp_path):
    f = tmp_path / 'requirements-prod.txt'
    f.write_text('requests\nflask>=1.0\n')
    assert scanner.scan_pypi_pins_only(str(f), 'requirements-prod.txt') == []


def test_continuation_lines_are_joined(tmp_path):
    f = tmp_path / 'requirements.txt'
    f.write_text('requests==2.0\nlitellm \\\n  == 1.107.0 \\\n  --hash=sha256:abc\n')
    got = [x for x in scanner.scan_python_deps(str(f), 'r') if 'Compromised' in x.title]
    assert len(got) == 1 and got[0].line == 2


@pytest.mark.parametrize('lock', ['uv.lock', 'pdm.lock', 'poetry.lock'])
def test_python_lockfiles_flag_the_pin(tmp_path, lock):
    (tmp_path / lock).write_text(
        '[[package]]\nname = "litellm"\nversion = "1.107.0"\nsource = {registry = "x"}\n')
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS_DIR, 'scan_dependencies.py'),
                        str(tmp_path), '--format', 'json', '--offline', '--skip-freshness'],
                       capture_output=True, text=True, timeout=60)
    data = json.loads(r.stdout)
    items = data['findings'] if isinstance(data, dict) else data
    assert any(i['title'].startswith('Compromised Package Version: litellm') for i in items)


def _run_hook(script, cmd, cwd):
    import subprocess
    payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': cmd}})
    return subprocess.run([sys.executable, os.path.join(SCRIPTS_DIR, script)], input=payload,
                          capture_output=True, text=True, timeout=60, cwd=str(cwd),
                          env={**os.environ, 'HOME': str(cwd), 'XDG_CACHE_HOME': str(cwd)})


def test_auto_scan_hook_reports_the_pin_end_to_end(tmp_path):
    r = _run_hook('auto_scan.py', 'pip install litellm==1.107.0', tmp_path)
    assert r.returncode == 0  # observe-only hook never blocks
    assert 'litellm==1.107.0' in r.stdout


def test_auto_scan_hook_quiet_for_clean_pin(tmp_path):
    r = _run_hook('auto_scan.py', 'pip install litellm==1.108.0', tmp_path)
    assert 'Compromised Package Version' not in r.stdout


def test_directory_scan_reaches_extra_requirements_files(tmp_path):
    (tmp_path / 'requirements').mkdir()
    (tmp_path / 'requirements' / 'prod.txt').write_text('litellm==1.107.0\n')
    (tmp_path / 'requirements-ci.txt').write_text('litellm==1.82.8\n')
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS_DIR, 'scan_dependencies.py'),
                        str(tmp_path), '--format', 'json', '--offline', '--skip-freshness'],
                       capture_output=True, text=True, timeout=60)
    data = json.loads(r.stdout)
    items = data['findings'] if isinstance(data, dict) else data
    files = {i['file'] for i in items if i['title'].startswith('Compromised Package Version')}
    assert files == {os.path.join('requirements', 'prod.txt'), 'requirements-ci.txt'}


@pytest.mark.parametrize('raw', [None, [], 'x', {'campaigns': None}, {'campaigns': []},
                                 {'campaigns': {'a': None}},
                                 {'campaigns': {'a': {'ecosystem': 'pypi', 'packages': None}}},
                                 {'campaigns': {'a': {'ecosystem': 'pypi', 'packages': {'p': 'x', 3: ['1']}}}},
                                 {'campaigns': {'a': {'ecosystem': ['pypi'], 'packages': {'p': ['1']}}}}])
def test_pypi_map_survives_hostile_data(raw):
    assert ioc_manager._pypi_version_map(raw) == {}


def test_pypi_map_ecosystem_label_is_case_insensitive_and_skips_non_strings():
    raw = {'campaigns': {'a': {'ecosystem': 'PyPI', 'packages': {'P': ['1.0', 2, None], 'q': ['*']}}}}
    assert ioc_manager._pypi_version_map(raw) == {'p': {'1.0': 'a'}}


def test_malformed_pypi_map_in_iocs_fails_open_in_the_gate(monkeypatch):
    real = ioc_manager.get_iocs()
    for bad in (None, [], {'litellm': None}, {'litellm': ['1.107.0']}, {'litellm': 5}):
        monkeypatch.setattr(ioc_manager, 'get_iocs',
                            lambda *a, _b=bad, **k: {**real, 'compromised_versions_pypi': _b})
        pre_scan.decide('pip install litellm==1.107.0')  # must not raise


@pytest.mark.parametrize('cmd', [
    'pip install requests \\\nlitellm==1.107.0',
    'pip install requests\npip install litellm==1.107.0',
    'pip install requests \\\r\n  litellm==1.107.0',
])
def test_multiline_install_pins_are_checked(cmd):
    assert pre_scan.decide(cmd)[0] == hook_adapter.DENY


def test_long_word_does_not_slow_the_gate():
    # shlex went quadratic on one long word (400 KB took ~14 s, past the
    # 10 s hook timeout, which the host treats as allow).
    import time
    cmd = 'pip install ' + 'a' * 400_000 + ' litellm==1.107.0'
    start = time.process_time()
    perm, _ = pre_scan.decide(cmd)
    assert time.process_time() - start < 2.0
    assert perm == hook_adapter.DENY


@pytest.mark.parametrize('line', [
    'litellm = "1.107.0"',
    'litellm = "=1.107.0"',
    'litellm = {version = "1.107.0"}',
])
def test_poetry_bare_version_pins_are_exact(tmp_path, line):
    path = tmp_path / 'pyproject.toml'
    path.write_text('[tool.poetry.dependencies]\npython = "^3.10"\n' + line + '\n')
    findings = scanner.scan_python_deps(str(path), 'pyproject.toml')
    assert any('litellm' in (str(f.title) + str(f.description)).lower() for f in findings)
