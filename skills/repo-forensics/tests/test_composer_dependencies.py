"""Tests for Composer (Packagist) coverage in scan_dependencies.py.

composer.json constraints run through the IOC name check, the compromised-
version check (strict_pin: ranges must NOT match), and OSV/Packagist
enrichment. composer.lock exact pins run the same checks non-strict. Platform
requisites (php, ext-*, lib-*, composer*) are never treated as packages.
"""

import json

import pytest

import scan_dependencies as scanner


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Keep OSV/KEV enrichment from touching the network in unit tests."""
    monkeypatch.setitem(scanner._VULN_STATE, "offline", True)
    yield
    scanner._VULN_STATE["offline"] = False
    scanner._VULN_STATE["queried"] = set()
    scanner._VULN_STATE["kev"] = None


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)
    return str(p), name


# --- composer.json ---------------------------------------------------------------

def test_composer_json_flags_compromised_exact(tmp_path):
    fp, rel = _write(tmp_path, 'composer.json', {
        "require": {"laravel-lang/lang": "15.29.5"}})
    fs = scanner.scan_composer_json(fp, rel)
    assert any(f.severity == 'critical' and 'laravel-lang/lang' in f.title
               for f in fs)


def test_composer_json_range_not_flagged(tmp_path):
    # strict_pin: a range that merely CONTAINS a compromised version must not
    # match it (same CRC-F1 rule as package.json).
    fp, rel = _write(tmp_path, 'composer.json', {
        "require": {"laravel-lang/lang": "^15.0"}})
    fs = scanner.scan_composer_json(fp, rel)
    assert not any('Compromised' in f.title for f in fs)


def test_composer_json_platform_requisites_skipped(tmp_path):
    fp, rel = _write(tmp_path, 'composer.json', {
        "require": {"php": "^8.2", "ext-json": "*", "ext-curl": "*",
                    "lib-pcre": ">=7.6", "composer-plugin-api": "^2.0",
                    "monolog/monolog": "^3.0"}})
    fs = scanner.scan_composer_json(fp, rel)
    assert fs == []


def test_composer_json_require_dev_scanned(tmp_path):
    fp, rel = _write(tmp_path, 'composer.json', {
        "require-dev": {"laravel-lang/http-statuses": "3.4.5"}})
    fs = scanner.scan_composer_json(fp, rel)
    assert any(f.severity == 'critical' for f in fs)


def test_composer_json_malformed_is_parse_error(tmp_path):
    fp, rel = _write(tmp_path, 'composer.json', '{broken')
    fs = scanner.scan_composer_json(fp, rel)
    assert len(fs) == 1 and fs[0].category == 'parse-error'


# --- composer.lock ---------------------------------------------------------------

def test_composer_lock_flags_exact_compromised_pin(tmp_path):
    fp, rel = _write(tmp_path, 'composer.lock', {
        "packages": [{"name": "laravel-lang/lang", "version": "15.29.5"},
                     {"name": "monolog/monolog", "version": "3.9.0"}],
        "packages-dev": []})
    fs = scanner.parse_composer_lock(fp, rel)
    hits = [f for f in fs if f.category == 'supply-chain']
    assert len(hits) == 1 and '15.29.5' in hits[0].title


def test_composer_lock_adjacent_clean_version_silent(tmp_path):
    fp, rel = _write(tmp_path, 'composer.lock', {
        "packages": [{"name": "laravel-lang/http-statuses", "version": "3.4.4"}]})
    fs = scanner.parse_composer_lock(fp, rel)
    assert not any(f.category == 'supply-chain' for f in fs)


def test_composer_lock_packages_dev_scanned(tmp_path):
    fp, rel = _write(tmp_path, 'composer.lock', {
        "packages": [],
        "packages-dev": [{"name": "laravel-lang/http-statuses", "version": "3.4.0"}]})
    fs = scanner.parse_composer_lock(fp, rel)
    assert any(f.severity == 'critical' for f in fs)


def test_composer_lock_malformed_is_parse_error(tmp_path):
    fp, rel = _write(tmp_path, 'composer.lock', '[1,2,')
    fs = scanner.parse_composer_lock(fp, rel)
    assert len(fs) == 1 and fs[0].category == 'parse-error'


def test_composer_lock_non_dict_silent(tmp_path):
    fp, rel = _write(tmp_path, 'composer.lock', '["not", "a", "dict"]')
    assert scanner.parse_composer_lock(fp, rel) == []
