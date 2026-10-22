"""Tests for the composer gate in pre_scan.py.

Composer plugins and autoload.files execute at install time, so
`composer require` must face the same IOC and compromised-version gate as
npm/pip. Tokens arrive as vendor/pkg, vendor/pkg:constraint or
vendor/pkg=constraint.
"""

import pytest

import pre_scan


def _decide(cmd):
    return pre_scan.decide(cmd)


class TestComposerGateBlocks:
    def test_exact_compromised_pin_blocked(self):
        perm, msg = _decide("composer require laravel-lang/lang:15.29.5")
        assert perm == pre_scan.hook_adapter.DENY
        assert '15.29.5' in msg

    def test_equals_form_blocked(self):
        perm, msg = _decide("composer require laravel-lang/http-statuses=3.4.5")
        assert perm == pre_scan.hook_adapter.DENY

    def test_range_that_can_resolve_to_compromised_blocked(self):
        perm, msg = _decide("composer require laravel-lang/lang:^15.0")
        assert perm == pre_scan.hook_adapter.DENY

    def test_global_require_blocked(self):
        perm, _ = _decide("composer global require laravel-lang/lang:15.29.5")
        assert perm == pre_scan.hook_adapter.DENY

    def test_phar_blocked(self):
        perm, _ = _decide("composer.phar require laravel-lang/lang:15.29.5")
        assert perm == pre_scan.hook_adapter.DENY

    def test_update_of_compromised_range_blocked(self):
        perm, _ = _decide("composer update laravel-lang/lang")
        # bare name: 15.29.5 is a pinned IOC, name itself not wildcard-malicious
        assert perm == pre_scan.hook_adapter.ALLOW


class TestComposerGateAllows:
    def test_clean_package(self):
        perm, _ = _decide("composer require monolog/monolog:^3.0")
        assert perm == pre_scan.hook_adapter.ALLOW

    def test_clean_exact_pin(self):
        perm, _ = _decide("composer require monolog/monolog:3.9.0")
        assert perm == pre_scan.hook_adapter.ALLOW

    def test_bare_install(self):
        perm, _ = _decide("composer install")
        assert perm == pre_scan.hook_adapter.ALLOW

    def test_local_path(self):
        perm, _ = _decide("composer require ./packages/local")
        assert perm == pre_scan.hook_adapter.ALLOW

    def test_adjacent_clean_version(self):
        perm, _ = _decide("composer require laravel-lang/http-statuses:3.4.4")
        assert perm == pre_scan.hook_adapter.ALLOW


class TestComposerTokenSplit:
    @pytest.mark.parametrize("token,base,ver", [
        ("monolog/monolog:^3.0", "monolog/monolog", "^3.0"),
        ("monolog/monolog=3.9.0", "monolog/monolog", "3.9.0"),
        ("monolog/monolog", "monolog/monolog", None),
        ("./packages/local", "./packages/local", None),
        ("vendor/pkg:dev-main", "vendor/pkg", "dev-main"),
    ])
    def test_split(self, token, base, ver):
        assert pre_scan.split_composer_name_version(token) == (base, ver)


# --- Gate gaps closed in the PR #68 follow-up (N6) ------------------------------

import time  # noqa: E402

import auto_scan  # noqa: E402

PINNED_IOC_FORMS = [
    # Composer accepts any unambiguous command prefix and the r/i/u/upgrade aliases
    "composer req laravel-lang/lang:15.29.5",
    "composer requ laravel-lang/lang:15.29.5",
    "composer r laravel-lang/lang:15.29.5",
    "composer i laravel-lang/lang:15.29.5",
    "composer inst laravel-lang/lang:15.29.5",
    "composer u laravel-lang/lang:15.29.5",
    "composer upd laravel-lang/lang:15.29.5",
    "composer upgrade laravel-lang/lang:15.29.5",
    "composer g req laravel-lang/lang:15.29.5",
    "composer --no-interaction req laravel-lang/lang:15.29.5",
    # stability flag does not change which release resolves
    "composer require laravel-lang/lang:15.29.5@stable",
    "composer require laravel-lang/http-statuses=3.4.5@dev",
    # space-separated version, Composer pairs it with the preceding package
    "composer require laravel-lang/lang 15.29.5",
    "composer require --dev laravel-lang/lang 15.29.5 monolog/monolog",
    # shell quotes never reach Composer
    'composer require "laravel-lang/lang:15.29.5"',
    "composer require 'laravel-lang/lang:15.29.5' --dev",
    # create-project vendor/pkg [directory] [version]
    "composer create-project laravel-lang/lang mydir 15.29.5",
    "composer create-project laravel-lang/lang:15.29.5 mydir",
    "composer create-project --prefer-dist laravel-lang/lang . 15.29.5",
    "composer cr laravel-lang/lang dir 15.29.5",
]


class TestComposerGateClosedGaps:
    @pytest.mark.parametrize("cmd", PINNED_IOC_FORMS)
    def test_pre_scan_denies(self, cmd):
        perm, _ = _decide(cmd)
        assert perm == pre_scan.hook_adapter.DENY, cmd

    @pytest.mark.parametrize("cmd", PINNED_IOC_FORMS)
    def test_auto_scan_extracts_same_pin(self, cmd):
        ptype, m = auto_scan.detect_install_command(cmd)
        assert ptype == 'composer_install', cmd
        names = auto_scan.extract_package_names(ptype, m)
        splits = [auto_scan.split_composer_name_version(n) for n in names]
        assert any(b.startswith('laravel-lang/') and v in ('15.29.5', '3.4.5')
                   for b, v in splits), (cmd, names)

    @pytest.mark.parametrize("cmd", [
        "composer require laravel-lang/lang && echo done",  # not a version
        "composer require monolog/monolog 3.9.0",
        "composer create-project laravel/laravel blog",
        "composer run-script test",
        "composer remove laravel-lang/lang",
        "composer init",
        "composer i",
        "composer u --lock",
    ])
    def test_allows(self, cmd):
        perm, _ = _decide(cmd)
        assert perm == pre_scan.hook_adapter.ALLOW, cmd

    @pytest.mark.parametrize("cmd", ["composer i", "composer u", "composer install --no-dev",
                                     "composer upgrade"])
    def test_auto_scan_bare_abbrev_is_lockfile_install(self, cmd):
        ptype, _ = auto_scan.detect_install_command(cmd)
        assert ptype in ('lockfile_install', 'composer_install'), cmd
        if ptype == 'composer_install':
            _, m = auto_scan.detect_install_command(cmd)
            assert auto_scan.extract_package_names(ptype, m) == []

    @pytest.mark.parametrize("token,base,ver", [
        ("laravel-lang/lang:15.29.5@stable", "laravel-lang/lang", "15.29.5"),
        ("vendor/pkg:^1.0@dev", "vendor/pkg", "^1.0"),
        ("vendor/pkg:@dev", "vendor/pkg", None),
    ])
    def test_split_strips_stability(self, token, base, ver):
        assert pre_scan.split_composer_name_version(token) == (base, ver)
        assert auto_scan.split_composer_name_version(token) == (base, ver)

    @pytest.mark.parametrize("cmd", [
        "composer " + "-x " * 20000 + "require a/b",
        "composer " + "r" * 50000,
        "composer create-project " + "a/b " * 20000,
        "composer require " + "a/b 1 " * 20000,
    ])
    def test_gate_is_linear(self, cmd):
        start = time.perf_counter()
        _decide(cmd)
        auto_scan.detect_install_command(cmd)
        assert time.perf_counter() - start < 1.0


class TestQuotedNpmTokens:
    """Same class as the quoted composer token: shell quotes hid the pin."""

    @pytest.mark.parametrize("cmd", [
        'npm install "keyv@6.0.0"',
        "npm i 'keyv@6.0.0'",
        'pnpm add "keyv@6.0.0"',
    ])
    def test_quoted_pinned_npm_denied(self, cmd):
        perm, _ = _decide(cmd)
        assert perm == pre_scan.hook_adapter.DENY, cmd

    def test_auto_scan_strips_quotes(self):
        ptype, m = auto_scan.detect_install_command('npm install "keyv@6.0.0"')
        assert auto_scan.extract_package_names(ptype, m) == ['keyv@6.0.0']
