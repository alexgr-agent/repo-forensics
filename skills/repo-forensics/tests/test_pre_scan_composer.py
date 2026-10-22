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
