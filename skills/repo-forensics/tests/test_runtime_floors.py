"""Tests for scan_runtime_floors.py (vulnerable runtime declarations).

Covers the PHP2Shell floors (CVE-2026-109618 / CVE-2026-109619): exact pins,
moving tags, composer constraints, and every extractor (composer.json,
composer.lock, Dockerfile, docker-compose, setup-php workflows).
"""

import json
import os
import subprocess
import sys

import pytest

import scan_runtime_floors as srf


SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts')


@pytest.fixture
def adv():
    runtimes, err = srf.load_runtime_floors()
    assert err is None
    raw = runtimes['php']['advisories'][0]
    return srf.Advisory('PHP', raw)


# --- Data file integrity -------------------------------------------------------

class TestDataFile:
    def test_loads(self):
        runtimes, err = srf.load_runtime_floors()
        assert err is None and 'php' in runtimes

    def test_php2shell_floors(self, adv):
        # Verified against php-src advisories GHSA-6wmf-4rv5-p3rp and
        # GHSA-w8hw-w9fx-j79w (2026-10-21).
        assert adv.floors[(8, 2)][1] == '8.2.35'
        assert adv.floors[(8, 3)][1] == '8.3.36'
        assert adv.floors[(8, 4)][1] == '8.4.27'
        assert adv.floors[(8, 5)][1] == '8.5.12'
        assert adv.eol_below == (8, 2)
        assert 'CVE-2026-109618' in adv.cves
        assert 'CVE-2026-109619' in adv.cves

    def test_missing_data_denies_clean(self, tmp_path):
        runtimes, err = srf.load_runtime_floors(str(tmp_path / 'nope.json'))
        assert runtimes == {} and err


# --- Version parsing -------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("8.1", (8, 1, 0)),
    ("8.1.4", (8, 1, 4)),
    ("v8.2.35", (8, 2, 35)),
    ("8.1.4RC2", (8, 1, 4)),
    (" 8.3.36 ", (8, 3, 36)),
])
def test_parse_version_ok(text, expected):
    assert srf.parse_version(text) == expected


@pytest.mark.parametrize("text", ["latest", "cli", "", "x.y.z"])
def test_parse_version_none(text):
    assert srf.parse_version(text) is None


# --- Exact pin checks ------------------------------------------------------------

@pytest.mark.parametrize("version,severity,kind", [
    ("7.4.33", "critical", "eol"),
    ("8.0.30", "critical", "eol"),
    ("8.1.31", "critical", "eol"),
    ("8.2.0", "high", "below-floor"),
    ("8.2.34", "high", "below-floor"),
    ("8.3.35", "high", "below-floor"),
    ("8.4.26", "high", "below-floor"),
    ("8.5.11", "high", "below-floor"),
])
def test_pin_vulnerable(adv, version, severity, kind):
    hit = adv.check_pin(version)
    assert hit is not None
    assert hit[0] == severity and hit[1] == kind


@pytest.mark.parametrize("version", ["8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13"])
def test_pin_patched_silent(adv, version):
    assert adv.check_pin(version) is None


# --- Constraint evaluation --------------------------------------------------------
#
# Only constraints that CANNOT resolve to a patched release may flag.

@pytest.mark.parametrize("constraint", [
    "^8.2",          # admits 8.2.35+
    "^8.1",          # composer caret: >=8.1 <9.0, admits patched branches
    ">=7.4",         # unbounded above
    ">=8.2 <9.0",
    "8.3.*",         # admits 8.3.36
    "~8.4",          # >=8.4 <9.0
    "^7.4 || ^8.2",  # second alternative admits patched
    "8.2.35",        # exact patched pin
    "8.5 - 8.5.12",  # hyphen range reaching the floor
    "*",
    "dev-main",      # unparseable: silent by posture
    ">=8.2, <8.4",   # comma separator
])
def test_constraint_admits_patched_silent(adv, constraint):
    assert srf.check_constraint(constraint, adv) is None


# A constraint is a declaration, not a deployment: it never goes above HIGH.
@pytest.mark.parametrize("constraint,severity,kind", [
    ("7.4.*", "high", "eol"),
    ("^7.4", "high", "eol"),
    ("~8.1.0", "high", "eol"),
    ("8.1.*", "high", "eol"),
    ("<8.2", "high", "eol"),
    ("8.1.4", "high", "eol"),          # exact pin on EOL branch
    ("7.4 || 8.1.*", "high", "eol"),
    (">=8.1 <8.2", "high", "eol"),
    ("<8.2.35", "high", "below-floor"),
    (">=8.2 <8.2.35", "high", "below-floor"),
    ("8.2.0 - 8.2.34", "high", "below-floor"),
    ("8.1.x-dev", "high", "eol"),      # dev head of an EOL branch
])
def test_constraint_unpatchable_flags(adv, constraint, severity, kind):
    hit = srf.check_constraint(constraint, adv)
    assert hit is not None, constraint
    assert hit[0] == severity and hit[1] == kind


@pytest.mark.parametrize("constraint", [
    # B1: branches newer than the listed floors (8.6 GA carries the fix; 9.x
    # does not exist yet) must never read as "every version is EOL".
    "^8.6", ">=8.6", "8.6.*", "~8.6.0", "^9.0", ">=9", "9.*",
    "^8.7", ">=8.1 <8.2 || ^9.0",
    # N5: a maintained branch's dev head contains the fix, like 8.3.*
    "8.3.x-dev", "8.x-dev",
])
def test_constraint_newer_or_dev_branch_silent(adv, constraint):
    assert srf.check_constraint(constraint, adv) is None, constraint


def test_constraint_tilde_8_3_admits_patch():
    # ~8.3.0 is >=8.3.0 <8.4.0, which admits 8.3.36 -> must be SILENT.
    runtimes, _ = srf.load_runtime_floors()
    adv = srf.Advisory('PHP', runtimes['php']['advisories'][0])
    assert srf.check_constraint("~8.3.0", adv) is None


# --- Docker tags -------------------------------------------------------------------

def _docker_hit(adv, tag):
    return srf._check_docker_tag(adv, tag, 'test', 'Dockerfile', 1, 'FROM php:' + tag)


# Image tags are what deploy: EOL and exact below-floor tags are CRITICAL.
@pytest.mark.parametrize("tag,sev", [
    ("7.4-apache", "critical"),
    ("8.1-fpm", "critical"),
    ("8.1.33", "critical"),
    ("8.2.34", "critical"),
    ("8.4.0-alpine", "critical"),
    ("7", "critical"),   # major-only tag on an EOL major
    ("5-apache", "critical"),
    ("8.2", "low"),      # moving minor tag: rebuild note
    ("8.3", "low"),
])
def test_docker_tag_flags(adv, tag, sev):
    f = _docker_hit(adv, tag)
    assert f is not None, tag
    assert f.severity == sev


@pytest.mark.parametrize("tag", ["latest", "cli", "apache", "8.2.35", "8.5.12-bookworm", "8",
                                 "8-fpm", "8.6", "8.6.0", "8.6-apache", "9", "9.0.1"])
def test_docker_tag_silent(adv, tag):
    assert _docker_hit(adv, tag) is None


# --- Extractors ---------------------------------------------------------------------

def _write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return str(p), name


def test_composer_json_platform_pin(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.json', json.dumps({
        "require": {"php": "^8.2"},
        "config": {"platform": {"php": "8.1.2"}}}))
    fs = srf.scan_composer_json(fp, rel, [adv])
    # config.platform is the runtime Composer EMULATES: EOL -> MEDIUM
    assert len(fs) == 1 and fs[0].severity == 'medium'


def test_composer_json_platform_pin_below_floor_low(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.json', json.dumps({
        "config": {"platform": {"php": "8.2.0"}}}))
    fs = srf.scan_composer_json(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'low'


def test_composer_json_eol_constraint(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.json', json.dumps({
        "require": {"php": "7.4.*", "monolog/monolog": "^3.0"}}))
    fs = srf.scan_composer_json(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'high'


def test_composer_json_php_8_6_constraint_silent(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.json', json.dumps({
        "require": {"php": "^8.6"}}))
    assert srf.scan_composer_json(fp, rel, [adv]) == []


def test_composer_json_clean(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.json', json.dumps({
        "require": {"php": ">=8.2"}}))
    assert srf.scan_composer_json(fp, rel, [adv]) == []


def test_composer_json_malformed(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.json', '{not json')
    assert srf.scan_composer_json(fp, rel, [adv]) == []


def test_composer_lock_platform_override(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.lock', json.dumps({
        "packages": [], "platform-overrides": {"php": "8.0.0"}}))
    fs = srf.scan_composer_lock(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'medium'


def test_composer_lock_platform_override_below_floor_low(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.lock', json.dumps({
        "packages": [], "platform-overrides": {"php": "8.3.1"}}))
    fs = srf.scan_composer_lock(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'low'


def test_composer_lock_platform_constraint(tmp_path, adv):
    fp, rel = _write(tmp_path, 'composer.lock', json.dumps({
        "packages": [], "platform": {"php": "7.4.*"}}))
    fs = srf.scan_composer_lock(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'high'


def test_dockerfile_arg_resolution(tmp_path, adv):
    fp, rel = _write(tmp_path, 'Dockerfile',
                     "ARG PHP_VERSION=8.1-fpm\nFROM php:${PHP_VERSION}\n")
    fs = srf.scan_dockerfile(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'critical'


def test_dockerfile_arg_default_syntax(tmp_path, adv):
    fp, rel = _write(tmp_path, 'Dockerfile', "FROM php:${PHP_VERSION:-8.2.30}\n")
    fs = srf.scan_dockerfile(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'critical'


@pytest.mark.parametrize("dockerfile", [
    "ARG PHP_VERSION=8.1\nFROM php:${PHP_VERSION}-fpm\n",       # var inside tag
    "ARG PHP_VERSION=8.1\nFROM php:$PHP_VERSION-fpm-alpine\n",  # bare $VAR
    'ARG V="8.0"\nFROM php:${V}\n',                             # quoted default
    "ARG V='7.4'\nFROM php:${V}-apache AS base\n",
    "FROM php:${PHP_VERSION:-8.1}-cli\n",                       # default inside tag
    "ARG MAJ=8\nARG MIN=1\nFROM php:${MAJ}.${MIN}-fpm\n",       # two refs
    "FROM php:7\n",                                             # EOL major-only
    "FROM php:5-apache\n",
])
def test_dockerfile_arg_forms_flag(tmp_path, adv, dockerfile):
    fp, rel = _write(tmp_path, 'Dockerfile', dockerfile)
    fs = srf.scan_dockerfile(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'critical', dockerfile


@pytest.mark.parametrize("dockerfile", [
    "ARG PHP_VERSION\nFROM php:${PHP_VERSION}-fpm\n",     # no default
    "ARG V=8.1\nFROM php:${V}-${FLAVOR}\n",               # a $ remains
    "ARG V=$BASE\nFROM php:${V}\n",                      # default is itself a var
    'ARG V="8.5.12"\nFROM php:${V}-fpm\n',                # patched
    "FROM php:8\n",                                       # maintained major
])
def test_dockerfile_arg_forms_silent(tmp_path, adv, dockerfile):
    fp, rel = _write(tmp_path, 'Dockerfile', dockerfile)
    assert srf.scan_dockerfile(fp, rel, [adv]) == [], dockerfile


def test_dockerfile_arg_unresolvable_silent(tmp_path, adv):
    fp, rel = _write(tmp_path, 'Dockerfile', "ARG PHP_VERSION\nFROM php:${PHP_VERSION}\n")
    assert srf.scan_dockerfile(fp, rel, [adv]) == []


def test_dockerfile_multistage_mixed(tmp_path, adv):
    fp, rel = _write(tmp_path, 'Dockerfile.prod',
                     "FROM php:8.5.12 AS ok\nFROM php:8.4.26 AS bad\n")
    fs = srf.scan_dockerfile(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].line == 2 and fs[0].severity == 'critical'


def test_compose_php_image(tmp_path, adv):
    fp, rel = _write(tmp_path, 'docker-compose.yml',
                     "services:\n  app:\n    image: php:7.4-apache\n")
    fs = srf.scan_compose(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'critical'


def test_compose_embedded_php_tag(tmp_path, adv):
    fp, rel = _write(tmp_path, 'docker-compose.yml',
                     "services:\n  wp:\n    image: wordpress:php8.0-apache\n")
    fs = srf.scan_compose(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'critical'


@pytest.mark.parametrize("line", [
    "image: wordpress:php8.1-apache",
    "image: reg:5000/wp:php8.3.0",
    'image: "x:php7.4@sha256:abc"',
    "image: library/php:8.0-fpm",
])
def test_compose_reference_forms_flag(tmp_path, adv, line):
    fp, rel = _write(tmp_path, 'docker-compose.yml', "services:\n  a:\n    " + line + "\n")
    fs = srf.scan_compose(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'critical', line


@pytest.mark.parametrize("line", [
    "image: reg:5000/wp",            # port colon, no tag
    "image: wordpress:6.5-apache",   # tag without php
    "image: php:8.5.12",
    "image: wordpress:php8.6-apache",
])
def test_compose_reference_forms_silent(tmp_path, adv, line):
    fp, rel = _write(tmp_path, 'docker-compose.yml', "services:\n  a:\n    " + line + "\n")
    assert srf.scan_compose(fp, rel, [adv]) == [], line


def test_compose_patched_silent(tmp_path, adv):
    fp, rel = _write(tmp_path, 'docker-compose.yml',
                     "services:\n  app:\n    image: php:8.4.27\n")
    assert srf.scan_compose(fp, rel, [adv]) == []


def test_workflow_matrix_and_pin(tmp_path, adv):
    fp, rel = _write(tmp_path, '.github/workflows/ci.yml',
                     "jobs:\n  t:\n    strategy:\n      matrix:\n"
                     "        php: ['7.4', '8.5']\n"
                     "    steps:\n      - uses: shivammathur/setup-php@v2\n"
                     "        with:\n          php-version: '8.1'\n")
    fs = srf.scan_workflow(fp, rel, [adv])
    sevs = sorted((f.line, f.severity) for f in fs)
    # matrix 7.4 (EOL) -> low; direct php-version 8.1 (EOL) -> medium;
    # 8.5 is a moving minor pin -> silent
    assert sevs == [(5, 'low'), (9, 'medium')]


def test_workflow_direct_exact_below_floor_low(tmp_path, adv):
    fp, rel = _write(tmp_path, '.github/workflows/ci.yml',
                     "steps:\n  - with:\n      php-version: '8.3.1'\n")
    fs = srf.scan_workflow(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'low'


def test_workflow_multiline_matrix(tmp_path, adv):
    fp, rel = _write(tmp_path, '.github/workflows/ci.yml',
                     "matrix:\n  php:\n    - '8.0'\n    - '8.5.12'\n")
    fs = srf.scan_workflow(fp, rel, [adv])
    assert len(fs) == 1 and fs[0].severity == 'low'


def test_workflow_patched_silent(tmp_path, adv):
    fp, rel = _write(tmp_path, '.github/workflows/ci.yml',
                     "steps:\n  - with:\n      php-version: '8.5.12'\n")
    assert srf.scan_workflow(fp, rel, [adv]) == []


# --- Driver end-to-end --------------------------------------------------------------

def _run_scanner(repo):
    return subprocess.run(
        [sys.executable, os.path.join(SCRIPTS_DIR, 'scan_runtime_floors.py'),
         str(repo), '--format', 'json'],
        capture_output=True, text=True, check=False)


def test_driver_full_repo(tmp_path):
    (tmp_path / 'composer.json').write_text(json.dumps(
        {"require": {"php": "7.4.*"}}))
    (tmp_path / 'Dockerfile').write_text("FROM php:8.2.0\n")
    sub = tmp_path / 'deploy'
    sub.mkdir()
    (sub / 'docker-compose.yaml').write_text("image: php:8.4.27\n")
    r = _run_scanner(tmp_path)
    assert r.returncode in (0, 1, 2), r.stderr
    findings = json.loads(r.stdout)
    sevs = {(f['file'], f['severity']) for f in findings}
    assert ('composer.json', 'high') in sevs
    assert ('Dockerfile', 'critical') in sevs
    assert not any(f['file'].endswith('docker-compose.yaml') for f in findings)


def test_driver_clean_repo(tmp_path):
    (tmp_path / 'composer.json').write_text(json.dumps({"require": {"php": "^8.4"}}))
    r = _run_scanner(tmp_path)
    assert r.returncode == 0
    assert json.loads(r.stdout) == []



def test_target_kind_routing():
    assert srf._target_kind('composer.json') == 'composer.json'
    assert srf._target_kind('sub/dir/composer.lock') == 'composer.lock'
    assert srf._target_kind('Dockerfile') == 'dockerfile'
    assert srf._target_kind('Dockerfile.prod') == 'dockerfile'
    assert srf._target_kind('app.Dockerfile') == 'dockerfile'
    assert srf._target_kind('docker-compose.yml') == 'compose'
    assert srf._target_kind('compose.yaml') == 'compose'
    assert srf._target_kind('.github/workflows/ci.yml') == 'workflow'
    assert srf._target_kind('.github/workflows/ci.yaml') == 'workflow'
    assert srf._target_kind('random.yml') is None
    assert srf._target_kind('workflows/ci.yml') is None


# --- Vendored dependencies (B3) ------------------------------------------------------

def test_driver_skips_vendor_composer_metadata(tmp_path):
    # A vendored library's `php` requirement is not this project's runtime.
    (tmp_path / 'composer.json').write_text(json.dumps({"require": {"php": ">=7.4"}}))
    lib = tmp_path / 'vendor' / 'old' / 'lib'
    lib.mkdir(parents=True)
    (lib / 'composer.json').write_text(json.dumps({"require": {"php": "^7.1"}}))
    (lib / 'composer.lock').write_text(json.dumps({"platform": {"php": "7.1.*"}}))
    nested = tmp_path / 'app' / 'vendor' / 'x' / 'y'
    nested.mkdir(parents=True)
    (nested / 'composer.json').write_text(json.dumps({"require": {"php": "5.6.*"}}))
    (tmp_path / 'Dockerfile').write_text("FROM php:8.5.12-apache\n")
    r = _run_scanner(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout) == []


def test_driver_vendor_named_project_dir_still_scanned(tmp_path):
    # Only a path SEGMENT named vendor is skipped, not names containing it.
    d = tmp_path / 'vendored-app'
    d.mkdir()
    (d / 'composer.json').write_text(json.dumps({"require": {"php": "7.4.*"}}))
    r = _run_scanner(tmp_path)
    findings = json.loads(r.stdout)
    assert [f['severity'] for f in findings] == ['high']


# --- Linear-time parsing on attacker-controlled lines (B2) ----------------------------

@pytest.mark.parametrize("name,line", [
    ('docker-compose.yml', 'image: ' + ':' * 100_000),
    ('docker-compose.yml', 'image: a' + ':a' * 50_000),
    ('docker-compose.yml', 'image: ' + 'php' * 33_000 + ':'),
    ('docker-compose.yml', 'image: ' + 'a/' * 50_000 + 'php'),
    ('docker-compose.yml', 'image: x:' + 'php9' * 25_000),
    ('Dockerfile', 'FROM ' + 'a/' * 50_000),
    ('Dockerfile', 'FROM php:' + '${A}' * 25_000),
    ('Dockerfile', 'FROM php:' + '${A:-' * 20_000),
    ('Dockerfile', 'ARG A=' + '$' * 100_000),
    ('.github/workflows/ci.yml', 'php: [' + '] ' * 50_000),
    ('.github/workflows/ci.yml', 'php-version: ' + ' ' * 100_000 + 'x'),
])
def test_pathological_lines_scan_fast(tmp_path, adv, name, line):
    import time
    fp, rel = _write(tmp_path, name, line + "\n")
    scan = {'docker-compose.yml': srf.scan_compose, 'Dockerfile': srf.scan_dockerfile,
            '.github/workflows/ci.yml': srf.scan_workflow}[name]
    start = time.perf_counter()
    scan(fp, rel, [adv])
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("constraint", [
    '>=' + '1.' * 50_000, '8 - ' + '-' * 100_000, '|' * 100_000, 'x' * 100_000 + '.x-dev',
    ' '.join(['^8.1'] * 20_000),
])
def test_pathological_constraints_fast(adv, constraint):
    import time
    start = time.perf_counter()
    srf.check_constraint(constraint, adv)
    assert time.perf_counter() - start < 1.0


# --- Data validation (N10) -------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"patched_floors": ["8.2.35"]},
    {"patched_floors": {"8.2": 8235}},
    {"cves": "CVE-2026-109618"},
    {"references": [1, 2]},
])
def test_malformed_advisory_fields_fail_loud(tmp_path, bad):
    adv = {"id": "x", "patched_floors": {"8.2": "8.2.35"}, "cves": ["C"]}
    adv.update(bad)
    p = tmp_path / 'floors.json'
    p.write_text(json.dumps({"schema_version": "1.0",
                             "runtimes": {"php": {"advisories": [adv]}}}))
    runtimes, err = srf.load_runtime_floors(str(p))
    assert runtimes == {} and err


def test_data_text_matches_sources(adv):
    # B4: no unsupported in-the-wild claim; EOL note names the backports.
    runtimes, _ = srf.load_runtime_floors()
    raw = runtimes['php']['advisories'][0]
    assert 'observed before public disclosure' not in raw['summary']
    assert 'backports' in raw['eol_note'] and 'receive no patch' not in raw['eol_note']
    assert adv.floors[(8, 6)][1] == '8.6.0'
