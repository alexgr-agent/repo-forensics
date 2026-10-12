"""Tests for ioc_manager.py.

Architecture reviewer (2026-04-05 plan review) flagged that ioc_manager.py
has zero direct test coverage despite being the single source of truth for
IOC data across all scanners. This file closes that gap.

Covers:
  - Hardcoded IOC set availability (fallback path)
  - Cache file round-trip (_save_cache / _load_cache)
  - Cache staleness (TTL handling)
  - fetch_remote_iocs error paths (no network, malformed JSON)
  - get_iocs() merge semantics
  - Shipped compromised_versions.json loader
  - Schema version gate
  - Wildcard merging into malicious_npm
"""

import json
import os
import time

import pytest

import ioc_manager


# ---------------------------------------------------------------------------
# Hardcoded IOC availability (fallback path)
# ---------------------------------------------------------------------------


class TestHardcodedFallback:
    """These sets must always be available even when no remote feed or
    shipped file is reachable. They're the last line of defense."""

    def test_hardcoded_c2_ips_not_empty(self):
        assert len(ioc_manager.HARDCODED_C2_IPS) > 0

    def test_hardcoded_malicious_npm_not_empty(self):
        assert len(ioc_manager.HARDCODED_MALICIOUS_NPM) > 0

    def test_hardcoded_malicious_pypi_not_empty(self):
        assert len(ioc_manager.HARDCODED_MALICIOUS_PYPI) > 0

    def test_hardcoded_malicious_domains_not_empty(self):
        assert len(ioc_manager.HARDCODED_MALICIOUS_DOMAINS) > 0

    def test_hardcoded_claud_code_present(self):
        """claud-code typosquat has been in the IOC list since v1."""
        assert "claud-code" in ioc_manager.HARDCODED_MALICIOUS_NPM

    def test_hardcoded_anthopic_present(self):
        assert "anthopic" in ioc_manager.HARDCODED_MALICIOUS_PYPI


# ---------------------------------------------------------------------------
# get_iocs() merge semantics
# ---------------------------------------------------------------------------


class TestGetIocs:
    def test_returns_all_expected_keys(self, tmp_path):
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        expected = {
            "c2_ips",
            "malicious_domains",
            "malicious_npm",
            "malicious_pypi",
            "malicious_pth_files",
            "compromised_versions",
        }
        assert expected.issubset(set(iocs.keys()))

    def test_malicious_npm_is_set(self, tmp_path):
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert isinstance(iocs["malicious_npm"], set)

    def test_compromised_versions_is_dict(self, tmp_path):
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert isinstance(iocs["compromised_versions"], dict)

    def test_returns_hardcoded_when_no_cache(self, tmp_path):
        """With an empty cache_dir, hardcoded fallback is used."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "claud-code" in iocs["malicious_npm"]

    def test_merges_cache_with_hardcoded(self, tmp_path):
        """Cached remote IOCs should be additive, not replace hardcoded."""
        cache = tmp_path / ioc_manager.CACHE_FILENAME
        cache.write_text(json.dumps({
            "malicious_npm_packages": ["newly-discovered-evil"],
            "_cached_at": time.time(),
        }))
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "claud-code" in iocs["malicious_npm"]  # hardcoded preserved
        assert "newly-discovered-evil" in iocs["malicious_npm"]  # remote added

    def test_includes_shipped_compromised_versions(self, tmp_path):
        """Marc Gadsdon's issue #5 fix: shipped JSON must be loaded."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "chalk" in iocs["compromised_versions"]
        assert "5.6.1" in iocs["compromised_versions"]["chalk"]

    def test_wildcard_packages_merged_into_malicious_npm(self, tmp_path):
        """Entirely-malicious packages (version=['*']) join malicious_npm set."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "darkslash" in iocs["malicious_npm"]  # ghost campaign
        assert "graphalgo" in iocs["malicious_npm"]  # Lazarus

    def test_version_pinned_not_in_malicious_npm(self, tmp_path):
        """Version-pinned packages stay in compromised_versions, not merged
        into the name-only set (otherwise clean versions would be flagged)."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        # chalk 5.6.1 is compromised but chalk is a legitimate package name
        assert "chalk" not in iocs["malicious_npm"]


# ---------------------------------------------------------------------------
# Cache round-trip (_save_cache / _load_cache)
# ---------------------------------------------------------------------------


class TestCacheRoundTrip:
    def test_save_load_round_trip(self, tmp_path):
        data = {
            "c2_ips": ["1.2.3.4"],
            "malicious_domains": ["evil.com"],
            "version": "test",
        }
        ioc_manager._save_cache(data, cache_dir=str(tmp_path))
        loaded = ioc_manager._load_cache(cache_dir=str(tmp_path))
        assert loaded is not None
        assert loaded["c2_ips"] == ["1.2.3.4"]
        assert loaded["version"] == "test"

    def test_save_does_not_mutate_input(self, tmp_path):
        """_save_cache must not add _cached_at to the caller's dict."""
        data = {"version": "x"}
        ioc_manager._save_cache(data, cache_dir=str(tmp_path))
        assert "_cached_at" not in data

    def test_load_returns_none_when_missing(self, tmp_path):
        assert ioc_manager._load_cache(cache_dir=str(tmp_path)) is None

    def test_load_returns_none_on_malformed_json(self, tmp_path):
        (tmp_path / ioc_manager.CACHE_FILENAME).write_text("not json{{{")
        assert ioc_manager._load_cache(cache_dir=str(tmp_path)) is None

    def test_stale_cache_returns_none(self, tmp_path):
        """Cache older than CACHE_MAX_AGE_HOURS must be treated as absent."""
        stale_time = time.time() - (ioc_manager.CACHE_MAX_AGE_HOURS + 1) * 3600
        cache = tmp_path / ioc_manager.CACHE_FILENAME
        cache.write_text(json.dumps({
            "version": "stale",
            "_cached_at": stale_time,
        }))
        assert ioc_manager._load_cache(cache_dir=str(tmp_path)) is None

    def test_fresh_cache_loads(self, tmp_path):
        cache = tmp_path / ioc_manager.CACHE_FILENAME
        cache.write_text(json.dumps({
            "version": "fresh",
            "_cached_at": time.time(),
        }))
        loaded = ioc_manager._load_cache(cache_dir=str(tmp_path))
        assert loaded is not None
        assert loaded["version"] == "fresh"


# ---------------------------------------------------------------------------
# fetch_remote_iocs error paths (do not touch the network in CI)
# ---------------------------------------------------------------------------


class TestFetchRemoteIocsErrors:
    def test_unreachable_url_returns_none(self):
        """An unreachable URL should return None, not raise."""
        result = ioc_manager.fetch_remote_iocs(
            feed_url="http://localhost:1/nonexistent"
        )
        assert result is None


# ---------------------------------------------------------------------------
# Shipped compromised_versions.json loader
# ---------------------------------------------------------------------------


class TestCompromisedVersionsLoader:
    def setup_method(self):
        """Reset the module-level cache before each test."""
        ioc_manager._reset_compromised_versions_cache()

    def test_loads_shipped_file(self):
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file()
        )
        assert len(version_map) > 0
        assert len(entirely_malicious) > 0
        assert raw is not None

    def test_chalk_is_version_pinned(self):
        version_map, _, _ = ioc_manager._load_compromised_versions_file()
        assert "chalk" in version_map
        assert "5.6.1" in version_map["chalk"]

    def test_darkslash_is_entirely_malicious(self):
        _, entirely_malicious, _ = ioc_manager._load_compromised_versions_file()
        assert "darkslash" in entirely_malicious

    def test_campaign_id_recorded_for_version_pinned(self):
        version_map, _, _ = ioc_manager._load_compromised_versions_file()
        assert version_map["chalk"]["5.6.1"] == "chalk_debug_sep_2025"

    def test_lowercase_keys(self):
        """All package keys should be lower-cased for case-insensitive lookup."""
        version_map, entirely_malicious, _ = (
            ioc_manager._load_compromised_versions_file()
        )
        for k in version_map.keys():
            assert k == k.lower()
        for k in entirely_malicious:
            assert k == k.lower()

    def test_missing_file_returns_empty(self, tmp_path):
        """Soft failure: missing file should not raise."""
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file(
                path=str(tmp_path / "nonexistent.json")
            )
        )
        assert version_map == {}
        assert entirely_malicious == set()
        assert raw is None

    def test_malformed_file_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json{{{")
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file(path=str(bad))
        )
        assert version_map == {}
        assert entirely_malicious == set()

    def test_schema_version_mismatch_rejected(self, tmp_path):
        """Incompatible schema version: refuse to load rather than misinterpret."""
        future = tmp_path / "future.json"
        future.write_text(json.dumps({
            "schema_version": "99.0",
            "campaigns": {
                "test": {
                    "packages": {"evil": ["1.0.0"]}
                }
            }
        }))
        version_map, entirely_malicious, _ = (
            ioc_manager._load_compromised_versions_file(path=str(future))
        )
        assert version_map == {}
        assert entirely_malicious == set()

    def test_missing_campaigns_field_returns_empty(self, tmp_path):
        no_campaigns = tmp_path / "no_campaigns.json"
        no_campaigns.write_text(json.dumps({"schema_version": "1.0"}))
        version_map, entirely_malicious, raw = (
            ioc_manager._load_compromised_versions_file(path=str(no_campaigns))
        )
        assert version_map == {}
        assert entirely_malicious == set()
        assert raw is not None  # file was parseable

    def test_malformed_campaign_skipped(self, tmp_path):
        """A single bad campaign entry should not abort the whole load."""
        mixed = tmp_path / "mixed.json"
        mixed.write_text(json.dumps({
            "schema_version": "1.0",
            "campaigns": {
                "bad": "this is not a dict",
                "good": {"packages": {"evil-pkg": ["1.0.0"]}},
            },
        }))
        version_map, _, _ = ioc_manager._load_compromised_versions_file(
            path=str(mixed)
        )
        # Bad campaign skipped, good campaign loaded
        assert "evil-pkg" in version_map

    def test_cache_memoizes_result(self):
        """Second call should return same object as first (cache hit)."""
        first = ioc_manager._get_compromised_versions()
        second = ioc_manager._get_compromised_versions()
        assert first is second

    def test_reset_cache_forces_reload(self):
        first = ioc_manager._get_compromised_versions()
        ioc_manager._reset_compromised_versions_cache()
        second = ioc_manager._get_compromised_versions()
        # Different objects after reset, but equal content
        assert first is not second
        assert first[0].keys() == second[0].keys()


class TestFeedURLHardening:
    """ADV-001: fetch_remote_iocs must reject non-https and non-allowlisted hosts."""

    def test_https_allowlisted_host_accepted(self):
        assert ioc_manager._validate_feed_url(
            "https://raw.githubusercontent.com/x/y/main/iocs.json"
        ) is True

    def test_http_rejected(self):
        assert ioc_manager._validate_feed_url(
            "http://raw.githubusercontent.com/x/y/main/iocs.json"
        ) is False

    def test_file_scheme_rejected(self):
        assert ioc_manager._validate_feed_url("file:///etc/passwd") is False

    def test_ftp_rejected(self):
        assert ioc_manager._validate_feed_url("ftp://example.com/iocs.json") is False

    def test_unknown_host_rejected(self):
        assert ioc_manager._validate_feed_url("https://evil.com/iocs.json") is False

    def test_private_ip_rejected(self):
        assert ioc_manager._validate_feed_url("https://127.0.0.1/iocs.json") is False

    def test_empty_url_rejected(self):
        assert ioc_manager._validate_feed_url("") is False
        assert ioc_manager._validate_feed_url(None) is False

    def test_fetch_rejects_bad_url_without_network(self, monkeypatch):
        # Ensure no socket is attempted
        def panic(*a, **kw):
            raise AssertionError("urlopen must not be called for rejected URL")
        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", panic)
        assert ioc_manager.fetch_remote_iocs("http://evil.com/iocs.json") is None


# ---------------------------------------------------------------------------
# May 2026 IOC additions (U4 update)
# ---------------------------------------------------------------------------


class TestMay2026IocAdditions:
    """Verify that all IOCs added in the U4 May 2026 update are present."""

    def test_megalodon_c2_ip_in_hardcoded_list(self):
        """216.126.225.129 (Megalodon CI campaign, May 2026) must be present."""
        assert "216.126.225.129" in ioc_manager.HARDCODED_C2_IPS

    def test_canisterworm_icp_domain_in_hardcoded_list(self):
        """ICP blockchain C2 domain (CanisterWorm, Apr 2026) must be present."""
        assert "cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io" in ioc_manager.HARDCODED_MALICIOUS_DOMAINS

    def test_chalk_tempalte_in_hardcoded_malicious_npm(self):
        """chalk-tempalte typosquat (Shai-Hulud copycat) must be flagged by name."""
        assert "chalk-tempalte" in ioc_manager.HARDCODED_MALICIOUS_NPM

    def test_legitimate_chalk_not_in_malicious_npm(self):
        """chalk (the real package) must NOT be in the malicious npm set — only
        specific compromised versions are tracked via compromised_versions.json."""
        assert "chalk" not in ioc_manager.HARDCODED_MALICIOUS_NPM

    def test_megalodon_c2_ip_in_get_iocs(self, tmp_path):
        """get_iocs() must surface the Megalodon C2 IP in the merged result."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "216.126.225.129" in iocs["c2_ips"]

    def test_canisterworm_domain_in_get_iocs(self, tmp_path):
        """get_iocs() must surface the ICP C2 domain in the merged result."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io" in iocs["malicious_domains"]

    def test_chalk_tempalte_in_get_iocs_malicious_npm(self, tmp_path):
        """get_iocs() malicious_npm set must include the chalk-tempalte typosquat."""
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert "chalk-tempalte" in iocs["malicious_npm"]


# ---------------------------------------------------------------------------
# KTD-11: signed IOC feed verify-on-load (additive, offline)
# ---------------------------------------------------------------------------

import sys as _sys  # noqa: E402

_REPO_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))), "scripts")
_sys.path.insert(0, _REPO_SCRIPTS)
import _ed25519_sign  # noqa: E402

_IOC_TEST_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
_IOC_TEST_PRIV, _IOC_TEST_PUB = _ed25519_sign.keypair(_IOC_TEST_SEED)


def _write_signed_cache(cache_dir, feed_dict, priv=_IOC_TEST_PRIV,
                        pub=_IOC_TEST_PUB, sign=True, tamper=False,
                        mark_seen=None):
    """Write a fresh IOC cache (.json) whose EXACT bytes are what the detached
    signature covers — mirroring the production single-file collapse. The .json
    that gets parsed and trusted IS the signed byte stream. Returns those bytes.

    `mark_seen` defaults to True whenever a signature is written (so the strip-
    detection sentinel is armed, matching production). Set it explicitly to
    simulate a genuinely-legacy install that has never seen a signature.
    """
    cache = os.path.join(cache_dir, ioc_manager.CACHE_FILENAME)
    # The signed cache carries NO _cached_at wrapper (can't sign a post-hoc
    # field); freshness comes from the file mtime, which is "now" on write.
    raw = json.dumps(feed_dict).encode("utf-8")
    with open(cache, "wb") as f:
        f.write(raw)
    if sign:
        sig = _ed25519_sign.sign(raw, priv, pub)
        if tamper:
            sig = bytearray(sig)
            sig[0] ^= 0x01
            sig = bytes(sig)
        with open(os.path.join(cache_dir, ioc_manager.SIG_CACHE_FILENAME), "wb") as f:
            f.write(sig)
    if mark_seen is None:
        mark_seen = sign
    if mark_seen:
        with open(os.path.join(cache_dir, ioc_manager.SIGNED_SEEN_FILENAME), "wb") as f:
            f.write(b"1")
    return raw


class TestIocSignatureVerifyOnLoad:
    """New-client behavior for the signed IOC feed; old-client behavior must be
    unaffected by the extra .sig file existing."""

    def test_valid_signature_not_degraded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "test", "malicious_domains": ["signed-evil.com"]}
        _write_signed_cache(str(tmp_path), feed)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_degraded"] is False
        assert iocs["_ioc_signature_invalid"] is False
        assert "signed-evil.com" in iocs["malicious_domains"]

    def test_invalid_signature_degraded_but_hardcoded_applies(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "test", "malicious_domains": ["poisoned.com"]}
        _write_signed_cache(str(tmp_path), feed, tamper=True)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_degraded"] is True
        assert iocs["_ioc_signature_invalid"] is True
        # Cached (untrusted) feed contents are NOT merged...
        assert "poisoned.com" not in iocs["malicious_domains"]
        # ...but the hardcoded fallback IOCs still apply.
        assert "claud-code" in iocs["malicious_npm"]

    def test_missing_sig_is_legacy_not_signature_degraded(self, tmp_path, monkeypatch):
        """A cache with NO .sig (old feed / old client) keeps merging and is not
        flagged signature-invalid — backward compatible."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "test", "malicious_domains": ["legacy-evil.com"]}
        _write_signed_cache(str(tmp_path), feed, sign=False)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is False
        assert iocs["_ioc_degraded"] is False  # fresh JSON cache present
        assert "legacy-evil.com" in iocs["malicious_domains"]

    def test_verify_helper_states(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        # None when no raw/sig present.
        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is None
        feed = {"version": "v", "malicious_domains": ["e.com"]}
        _write_signed_cache(str(tmp_path), feed)
        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is True

    def test_extra_sig_file_does_not_break_old_path(self, tmp_path, monkeypatch):
        """The presence of the .sig file must not break the plain cache-merge
        path that old clients rely on (they never read it)."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_npm_packages": ["extra-evil"]}
        _write_signed_cache(str(tmp_path), feed)
        # Simulate old client: just load the JSON cache directly.
        cached = ioc_manager._load_cache(cache_dir=str(tmp_path))
        assert cached is not None
        assert "extra-evil" in cached.get("malicious_npm_packages", [])


class TestIocUpdateAcceptance:
    def test_invalid_signature_fails_without_replacing_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        previous = b'{"version":"previous","malicious_domains":[]}'
        (tmp_path / ioc_manager.CACHE_FILENAME).write_bytes(previous)
        feed = {"version": "new", "malicious_domains": ["bad.example"]}
        raw = json.dumps(feed, sort_keys=True).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs",
                            lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: b"x" * 64)

        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))

        assert not ok
        assert "signature invalid" in msg
        assert (tmp_path / ioc_manager.CACHE_FILENAME).read_bytes() == previous

    def test_missing_signature_fails_without_unsigned_fallback(self, tmp_path, monkeypatch):
        feed = {"version": "new", "malicious_domains": []}
        raw = json.dumps(feed).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs",
                            lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: None)

        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))

        assert not ok
        assert "could not download the feed signature" in msg
        assert not (tmp_path / ioc_manager.CACHE_FILENAME).exists()

    def test_interrupted_pair_commit_restores_last_known_good(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        old = {"version": "old", "c2_ips": [], "malicious_domains": ["old.example"],
               "malicious_npm_packages": [], "malicious_pypi_packages": []}
        new = {"version": "new", "c2_ips": [], "malicious_domains": ["new.example"],
               "malicious_npm_packages": [], "malicious_pypi_packages": []}
        old_raw = json.dumps(old, sort_keys=True).encode()
        new_raw = json.dumps(new, sort_keys=True).encode()
        old_sig = _ed25519_sign.sign(old_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        new_sig = _ed25519_sign.sign(new_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        ioc_manager._save_signed_cache(old_raw, old_sig, str(tmp_path))

        real_write = ioc_manager._atomic_write_bytes
        failed = {"done": False}

        def fail_current_signature_once(path, data, mode=0o600):
            if path == ioc_manager._sig_cache_path(str(tmp_path)) and not failed["done"]:
                failed["done"] = True
                raise OSError("injected signature rename failure")
            return real_write(path, data, mode=mode)

        monkeypatch.setattr(ioc_manager, "_atomic_write_bytes", fail_current_signature_once)
        with pytest.raises(OSError, match="injected"):
            ioc_manager._save_signed_cache(new_raw, new_sig, str(tmp_path))

        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is True
        assert ioc_manager._load_cache(str(tmp_path))["version"] == "old"

    def test_mismatched_current_pair_recovers_previous_after_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        old = {"version": "old", "c2_ips": [], "malicious_domains": [],
               "malicious_npm_packages": [], "malicious_pypi_packages": []}
        new = dict(old, version="new")
        old_raw = json.dumps(old, sort_keys=True).encode()
        new_raw = json.dumps(new, sort_keys=True).encode()
        old_sig = _ed25519_sign.sign(old_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        new_sig = _ed25519_sign.sign(new_raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        ioc_manager._save_signed_cache(old_raw, old_sig, str(tmp_path))
        ioc_manager._save_signed_cache(new_raw, new_sig, str(tmp_path))
        # Simulate power loss after the JSON rename but before its matching sig.
        ioc_manager._atomic_write_bytes(ioc_manager._cache_path(str(tmp_path)), old_raw)

        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is True
        assert ioc_manager._load_cache(str(tmp_path))["version"] == "old"


# ---------------------------------------------------------------------------
# Torture-room regressions: signature must protect the TRUSTED bytes (FIX 3)
# ---------------------------------------------------------------------------

class TestIocSignatureBindsTrustedBytes:
    """The .sig must verify over the SAME .json bytes that get parsed and
    trusted. A same-user attacker editing the .json must be caught, and a
    previously-signed install whose .sig is later stripped must degrade."""

    def test_editing_trusted_json_is_caught(self, tmp_path, monkeypatch):
        """Edit the .json that get_iocs actually parses; signature now covers
        those very bytes, so verification fails and the poisoned edit is NOT
        trusted (the old dual-file scheme verified a different file)."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["real-evil.com"]}
        _write_signed_cache(str(tmp_path), feed)
        # Attacker edits the TRUSTED .json in place: removes a known-malicious
        # domain (defanging) and injects a benign-looking allowlist entry.
        cache = os.path.join(str(tmp_path), ioc_manager.CACHE_FILENAME)
        with open(cache, "wb") as f:
            f.write(json.dumps({"version": "v", "malicious_domains": []}).encode())
        # Signature no longer matches the edited bytes -> invalid -> degraded.
        assert ioc_manager._verify_ioc_cache_signature(str(tmp_path)) is False
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is True
        assert iocs["_ioc_degraded"] is True
        # The attacker-edited (untrusted) feed contents are not merged; only the
        # hardcoded fallback survives.
        assert "real-evil.com" not in iocs["malicious_domains"]
        assert "claud-code" in iocs["malicious_npm"]

    def test_stripped_signature_on_signed_install_degrades(self, tmp_path, monkeypatch):
        """A .sig that USED to be present and is now gone must degrade rather
        than silently trust the unsigned cache."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["was-signed.com"]}
        _write_signed_cache(str(tmp_path), feed)  # arms the signed-seen sentinel
        # Attacker strips the signature, leaving the (now unsigned) cache.
        os.unlink(os.path.join(str(tmp_path), ioc_manager.SIG_CACHE_FILENAME))
        assert ioc_manager._has_seen_signed(str(tmp_path)) is True
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is True
        assert iocs["_ioc_degraded"] is True
        assert "was-signed.com" not in iocs["malicious_domains"]

    def test_genuinely_legacy_unsigned_install_still_trusts(self, tmp_path, monkeypatch):
        """An install that has NEVER seen a signature (no sentinel) keeps the
        backward-compatible merge for a plain unsigned cache."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["legacy.com"]}
        _write_signed_cache(str(tmp_path), feed, sign=False, mark_seen=False)
        assert ioc_manager._has_seen_signed(str(tmp_path)) is False
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is False
        assert iocs["_ioc_degraded"] is False
        assert "legacy.com" in iocs["malicious_domains"]

    def test_valid_signature_arms_sentinel_on_read(self, tmp_path, monkeypatch):
        """First valid verification during a read arms the strip-detection
        sentinel even if it was not pre-written."""
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        feed = {"version": "v", "malicious_domains": ["e.com"]}
        _write_signed_cache(str(tmp_path), feed, mark_seen=False)
        assert ioc_manager._has_seen_signed(str(tmp_path)) is False
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_signature_invalid"] is False
        assert ioc_manager._has_seen_signed(str(tmp_path)) is True


# ---------------------------------------------------------------------------
# Paired-file published-feed gate (issue #54)
# ---------------------------------------------------------------------------


def _publish(dirpath, name, payload=b'{"version":"t"}', tamper=False, sig=None):
    raw = payload
    (dirpath / name).write_bytes(raw)
    if sig is None:
        sig = _ed25519_sign.sign(raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        if tamper:
            sig = bytes([sig[0] ^ 1]) + sig[1:]
    (dirpath / (name + ".sig")).write_bytes(sig)


class TestPublishedFeedGate:
    @pytest.fixture(autouse=True)
    def _key(self, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())

    def _both(self, d, **kw):
        _publish(d, "latest.json", **kw)
        _publish(d, "rulepacks.json")

    def test_valid_pair_passes(self, tmp_path):
        self._both(tmp_path)
        ok, res = ioc_manager.verify_published_feed(str(tmp_path))
        assert ok and all(r[1] for r in res)

    def test_invalid_sig_fails_loudly(self, tmp_path):
        self._both(tmp_path, tamper=True)
        ok, res = ioc_manager.verify_published_feed(str(tmp_path))
        assert not ok
        assert dict((n, g) for n, g, _ in res) == {"latest.json": False, "rulepacks.json": True}
        assert "re-sign" in [r for r in res if r[0] == "latest.json"][0][2]

    def test_missing_sig_fails(self, tmp_path):
        self._both(tmp_path)
        (tmp_path / "latest.json.sig").unlink()
        assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    def test_missing_feed_fails(self, tmp_path):
        self._both(tmp_path)
        (tmp_path / "rulepacks.json").unlink()
        assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    def test_tampered_feed_fails(self, tmp_path):
        self._both(tmp_path)
        (tmp_path / "latest.json").write_bytes(b'{"version":"evil"}')
        assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    @pytest.mark.parametrize("sig", [b"", b"x" * 63, b"x" * 65, b"x" * 5000])
    def test_bad_sig_lengths_fail(self, tmp_path, sig):
        self._both(tmp_path, sig=sig)
        assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    def test_non_json_feed_fails(self, tmp_path):
        self._both(tmp_path, payload=b"not json")
        assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    def test_signature_from_other_key_fails(self, tmp_path):
        other_priv, other_pub = _ed25519_sign.keypair(b"\x07" * 32)
        raw = b'{"version":"t"}'
        self._both(tmp_path)
        (tmp_path / "latest.json.sig").write_bytes(_ed25519_sign.sign(raw, other_priv, other_pub))
        assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    def test_cli_exit_codes(self, tmp_path, monkeypatch, capsys):
        self._both(tmp_path)
        monkeypatch.setattr("sys.argv", ["ioc_manager.py", "--verify-published", str(tmp_path)])
        with pytest.raises(SystemExit) as e:
            ioc_manager.main()
        assert e.value.code == 0
        (tmp_path / "latest.json.sig").unlink()
        with pytest.raises(SystemExit) as e:
            ioc_manager.main()
        assert e.value.code == 1
        assert "[!] latest.json" in capsys.readouterr().out

    def test_update_failure_marks_stale_cache_explicitly(self, tmp_path, monkeypatch):
        (tmp_path / ioc_manager.CACHE_FILENAME).write_bytes(b'{"version":"old"}')
        old = time.time() - 72 * 3600
        os.utime(tmp_path / ioc_manager.CACHE_FILENAME, (old, old))
        feed = {"version": "n", "c2_ips": ["1.1.1.1"]}
        raw = json.dumps(feed).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: b"x" * 64)
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and "STALE" in msg and "re-sign" in msg
        assert ioc_manager.cache_status(str(tmp_path))["stale"] is True

    def test_cache_status_absent_is_stale(self, tmp_path):
        assert ioc_manager.cache_status(str(tmp_path)) == {"present": False, "age_hours": None, "stale": True, "refresh_refused": False}

    def test_no_bypass_parameter_exists(self):
        import inspect
        assert list(inspect.signature(ioc_manager.verify_published_feed).parameters) == ["iocs_dir"]
        assert "--verify-published" in inspect.getsource(ioc_manager.main)


class TestPublishedFeedGateRound2:
    @pytest.fixture(autouse=True)
    def _key(self, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())

    def test_crlf_converted_feed_fails(self, tmp_path):
        _publish(tmp_path, "latest.json", payload=b'{\n"version":"t"\n}')
        _publish(tmp_path, "rulepacks.json")
        (tmp_path / "latest.json").write_bytes(b'{\r\n"version":"t"\r\n}')
        assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    def test_trailing_newline_and_hex_sig_rejected(self, tmp_path):
        raw = b'{"version":"t"}'
        good = _ed25519_sign.sign(raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        for bad in (good + b"\n", good.hex().encode()):
            _publish(tmp_path, "latest.json", sig=bad)
            _publish(tmp_path, "rulepacks.json")
            assert not ioc_manager.verify_published_feed(str(tmp_path))[0]

    def test_missing_directory_fails(self, tmp_path):
        assert not ioc_manager.verify_published_feed(str(tmp_path / "nope"))[0]


class TestRefusedRefreshStateTransition:
    @pytest.fixture(autouse=True)
    def _key(self, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())

    def _fresh_cache(self, d):
        _write_signed_cache(str(d), {"version": "good", "malicious_domains": ["good-evil.com"]})

    def _bad_remote(self, monkeypatch, sig=b"x" * 64):
        feed = {"version": "n", "c2_ips": ["1.1.1.1"], "malicious_domains": [],
                "malicious_npm_packages": [], "malicious_pypi_packages": []}
        raw = json.dumps(feed).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: sig)

    def test_fresh_cache_becomes_stale_and_degraded_after_refusal(self, tmp_path, monkeypatch):
        self._fresh_cache(tmp_path)
        before = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert before["_ioc_degraded"] is False
        assert ioc_manager.cache_status(str(tmp_path))["stale"] is False
        self._bad_remote(monkeypatch)
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and "STALE" in msg
        st = ioc_manager.cache_status(str(tmp_path))
        assert st["stale"] is True and st["refresh_refused"] is True
        after = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert after["_ioc_degraded"] is True
        assert after["_ioc_refresh_refused"] is True
        # last-known-good, still-verifying cache content is preserved and used
        assert "good-evil.com" in after["malicious_domains"]

    def test_sig_404_marks_stale(self, tmp_path, monkeypatch):
        self._fresh_cache(tmp_path)
        self._bad_remote(monkeypatch, sig=None)
        monkeypatch.setattr(ioc_manager, "_last_fetch_absent", True)
        ok, _ = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and ioc_manager.get_iocs(cache_dir=str(tmp_path))["_ioc_degraded"] is True

    def test_sig_download_timeout_does_not_mark(self, tmp_path, monkeypatch):
        self._fresh_cache(tmp_path)
        self._bad_remote(monkeypatch, sig=None)
        monkeypatch.setattr(ioc_manager, "_last_fetch_absent", False)
        ok, _ = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok
        assert not ioc_manager.refresh_refused(str(tmp_path))
        assert ioc_manager.get_iocs(cache_dir=str(tmp_path))["_ioc_degraded"] is False

    def test_real_fetch_timeout_vs_404_flag(self, monkeypatch):
        import urllib.request, urllib.error, socket
        monkeypatch.setattr(ioc_manager, "_validate_feed_url", lambda u: True)
        def boom(exc):
            def f(*a, **k): raise exc
            return f
        monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda self, *a, **k: boom(socket.timeout("t"))())
        assert ioc_manager._fetch_url_bytes("https://x/y", 10) is None
        assert ioc_manager._last_fetch_absent is False
        monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda self, *a, **k: boom(
            urllib.error.HTTPError("https://x/y", 503, "no", {}, None))())
        assert ioc_manager._fetch_url_bytes("https://x/y", 10) is None
        assert ioc_manager._last_fetch_absent is False
        monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda self, *a, **k: boom(
            urllib.error.HTTPError("https://x/y", 404, "no", {}, None))())
        assert ioc_manager._fetch_url_bytes("https://x/y", 10) is None
        assert ioc_manager._last_fetch_absent is True

    def test_repair_hint_names_command_for_each_artifact(self, tmp_path, monkeypatch):
        for bad, want, notwant in (("latest.json", "--ioc-only", None),
                                   ("rulepacks.json", "--allow-unchanged", "--ioc-only")):
            _publish(tmp_path, "latest.json", tamper=(bad == "latest.json"))
            _publish(tmp_path, "rulepacks.json", tamper=(bad == "rulepacks.json"))
            _, res = ioc_manager.verify_published_feed(str(tmp_path))
            reason = [r for r in res if r[0] == bad][0][2]
            assert want in reason
            if notwant:
                assert notwant not in reason

    def test_pre_scan_warning_text_for_refused_but_served_cache(self, tmp_path, monkeypatch, capsys):
        import pre_scan
        self._fresh_cache(tmp_path)
        self._bad_remote(monkeypatch)
        ioc_manager.update_iocs(cache_dir=str(tmp_path))
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        pre_scan.check_ioc_packages(["left-pad"], iocs=iocs)
        err = capsys.readouterr().err
        assert "last verified cached feed" in err
        assert "Only hardcoded IOCs" not in err
        pre_scan.check_ioc_packages(["left-pad"], iocs={"_ioc_degraded": True})
        assert "Only hardcoded IOCs" in capsys.readouterr().err

    def test_verified_refresh_clears_stale(self, tmp_path, monkeypatch):
        self._fresh_cache(tmp_path)
        self._bad_remote(monkeypatch)
        ioc_manager.update_iocs(cache_dir=str(tmp_path))
        feed = {"version": "v2", "c2_ips": ["2.2.2.2"], "malicious_domains": ["x.com"],
                "malicious_npm_packages": [], "malicious_pypi_packages": []}
        raw = json.dumps(feed).encode()
        sig = _ed25519_sign.sign(raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: sig)
        ok, _ = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert ok
        assert ioc_manager.cache_status(str(tmp_path))["stale"] is False
        assert ioc_manager.get_iocs(cache_dir=str(tmp_path))["_ioc_degraded"] is False

    def test_network_failure_does_not_mark_refused(self, tmp_path, monkeypatch):
        self._fresh_cache(tmp_path)
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (None, None))
        ok, _ = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and not ioc_manager.refresh_refused(str(tmp_path))


class TestIocOnlyResign:
    """The maintainer re-sign path for issue #54: --ioc-only must work with no
    rule-pack changes and must not touch the rule-pack bundle."""

    def _publisher(self, tmp_path, monkeypatch):
        import importlib.util
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        spec = importlib.util.spec_from_file_location(
            "sign_rulepacks_ioc_only", os.path.join(root, "scripts", "sign_rulepacks.py"))
        pub = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pub)
        monkeypatch.setattr(pub, "_IOCS_DIR", str(tmp_path))
        monkeypatch.setattr(pub, "_LATEST_PATH", str(tmp_path / "latest.json"))
        monkeypatch.setattr(pub, "_BUNDLE_PATH", str(tmp_path / "rulepacks.json"))
        return pub

    def test_ioc_only_signs_latest_and_leaves_bundle_untouched(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        pub = self._publisher(tmp_path, monkeypatch)
        (tmp_path / "latest.json").write_bytes(b'{"version":"t"}')
        (tmp_path / "latest.json.sig").write_bytes(b"\x00" * 64)  # invalid, like live
        (tmp_path / "rulepacks.json").write_bytes(b'{"bundle":1}')
        (tmp_path / "rulepacks.json.sig").write_bytes(b"B" * 64)
        rc = pub.main(["--ioc-only", "--seed-hex", _IOC_TEST_SEED.hex()])
        assert rc == 0
        assert ioc_manager._verify_ioc_bytes(
            (tmp_path / "latest.json").read_bytes(), (tmp_path / "latest.json.sig").read_bytes())
        assert (tmp_path / "rulepacks.json").read_bytes() == b'{"bundle":1}'
        assert (tmp_path / "rulepacks.json.sig").read_bytes() == b"B" * 64

    def test_ioc_only_missing_latest_fails(self, tmp_path, monkeypatch):
        pub = self._publisher(tmp_path, monkeypatch)
        assert pub.main(["--ioc-only", "--seed-hex", _IOC_TEST_SEED.hex()]) == 1

    def test_ioc_only_requires_key_and_rejects_build_only(self, tmp_path, monkeypatch):
        pub = self._publisher(tmp_path, monkeypatch)
        with pytest.raises(SystemExit):
            pub.main(["--ioc-only"])
        with pytest.raises(SystemExit):
            pub.main(["--ioc-only", "--build-only"])


class TestMessagesAndLiveVerify:
    @pytest.fixture(autouse=True)
    def _key(self, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())

    def _remote(self, monkeypatch, sig):
        feed = {"version": "n", "c2_ips": ["1.1.1.1"], "malicious_domains": [],
                "malicious_npm_packages": [], "malicious_pypi_packages": []}
        raw = json.dumps(feed).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: sig)

    def test_transport_message_does_not_claim_stale(self, tmp_path, monkeypatch):
        _write_signed_cache(str(tmp_path), {"version": "g", "malicious_domains": []})
        self._remote(monkeypatch, None)
        monkeypatch.setattr(ioc_manager, "_last_fetch_absent", False)
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and "network failure" in msg and "still fresh" in msg
        assert "marked STALE" not in msg and "stale" not in msg.lower().replace("still fresh", "")

    def test_404_message_says_refused_and_stale(self, tmp_path, monkeypatch):
        _write_signed_cache(str(tmp_path), {"version": "g", "malicious_domains": []})
        self._remote(monkeypatch, None)
        monkeypatch.setattr(ioc_manager, "_last_fetch_absent", True)
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and "404" in msg and "marked STALE" in msg

    def test_invalid_message_truthful_even_if_marker_unwritable(self, tmp_path, monkeypatch):
        _write_signed_cache(str(tmp_path), {"version": "g", "malicious_domains": []})
        self._remote(monkeypatch, b"x" * 64)
        monkeypatch.setattr(ioc_manager, "_mark_refresh_refused", lambda *a, **k: None)
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and "still fresh" in msg and "marked STALE" not in msg

    def _live(self, monkeypatch, table):
        def fetch(url, cap):
            v = table[url]
            ioc_manager._last_fetch_absent = (v == "404")
            return None if v in ("404", "net") else v
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", fetch)

    def _urls(self):
        return (("latest.json", "https://x/latest.json"), ("rulepacks.json", "https://x/rp.json"))

    def _good(self, raw):
        return _ed25519_sign.sign(raw, _IOC_TEST_PRIV, _IOC_TEST_PUB)

    def test_live_all_good(self, monkeypatch):
        a, b = b'{"a":1}', b'{"b":2}'
        self._live(monkeypatch, {"https://x/latest.json": a, "https://x/latest.json.sig": self._good(a),
                                 "https://x/rp.json": b, "https://x/rp.json.sig": self._good(b)})
        assert ioc_manager.verify_live_feed(self._urls())[0] == 0

    def test_live_bad_sig_is_1(self, monkeypatch):
        a, b = b'{"a":1}', b'{"b":2}'
        self._live(monkeypatch, {"https://x/latest.json": a, "https://x/latest.json.sig": b"x" * 64,
                                 "https://x/rp.json": b, "https://x/rp.json.sig": self._good(b)})
        code, res = ioc_manager.verify_live_feed(self._urls())
        assert code == 1 and res[0][1] is False and "--ioc-only" in res[0][2]

    def test_live_404_is_1_network_only_is_3(self, monkeypatch):
        a, b = b'{"a":1}', b'{"b":2}'
        base = {"https://x/latest.json": a, "https://x/latest.json.sig": self._good(a),
                "https://x/rp.json": b, "https://x/rp.json.sig": self._good(b)}
        self._live(monkeypatch, dict(base, **{"https://x/rp.json.sig": "404"}))
        assert ioc_manager.verify_live_feed(self._urls())[0] == 1
        self._live(monkeypatch, dict(base, **{"https://x/rp.json": "net"}))
        assert ioc_manager.verify_live_feed(self._urls())[0] == 3

    def test_live_bad_beats_network_unknown(self, monkeypatch):
        a = b'{"a":1}'
        self._live(monkeypatch, {"https://x/latest.json": a, "https://x/latest.json.sig": b"x" * 64,
                                 "https://x/rp.json": "net", "https://x/rp.json.sig": "net"})
        assert ioc_manager.verify_live_feed(self._urls())[0] == 1


class TestOversizeIsRejectionNotNetwork:
    @pytest.fixture(autouse=True)
    def _key(self, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())
        monkeypatch.setattr(ioc_manager, "_last_fetch_absent", False)
        monkeypatch.setattr(ioc_manager, "_last_fetch_rejected", False)

    def _urlopen(self, monkeypatch, payload):
        import urllib.request, io
        class R(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False
        monkeypatch.setattr(ioc_manager, "_validate_feed_url", lambda u: True)
        monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda self, *a, **k: R(payload))

    def test_fetch_flags_oversize_not_absent(self, monkeypatch):
        self._urlopen(monkeypatch, b"x" * 100)
        assert ioc_manager._fetch_url_bytes("https://x/y", 10) is None
        assert ioc_manager._last_fetch_rejected is True
        assert ioc_manager._last_fetch_absent is False
        self._urlopen(monkeypatch, b"x" * 5)
        assert ioc_manager._fetch_url_bytes("https://x/y", 10) == b"x" * 5
        assert ioc_manager._last_fetch_rejected is False

    def test_live_oversize_sig_is_exit_1(self, monkeypatch):
        a = b'{"a":1}'
        good = _ed25519_sign.sign(a, _IOC_TEST_PRIV, _IOC_TEST_PUB)
        def fetch(url, cap):
            ioc_manager._last_fetch_rejected = url.endswith(".sig") and "latest" in url
            ioc_manager._last_fetch_absent = False
            if url.endswith(".sig"):
                return None if ioc_manager._last_fetch_rejected else good
            return a
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", fetch)
        code, res = ioc_manager.verify_live_feed((("latest.json", "https://x/latest.json"),))
        assert code == 1 and "REJECTED" in res[0][2]

    def test_live_oversize_content_is_exit_1(self, monkeypatch):
        def fetch(url, cap):
            ioc_manager._last_fetch_rejected = not url.endswith(".sig")
            ioc_manager._last_fetch_absent = False
            return None if not url.endswith(".sig") else b"x" * 64
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", fetch)
        code, _ = ioc_manager.verify_live_feed((("latest.json", "https://x/latest.json"),))
        assert code == 1

    def test_update_oversize_sig_marks_refused(self, tmp_path, monkeypatch):
        _write_signed_cache(str(tmp_path), {"version": "g", "malicious_domains": []})
        feed = {"version": "n", "c2_ips": ["1.1.1.1"]}
        raw = json.dumps(feed).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (feed, raw))
        def fetch(*a, **k):
            ioc_manager._last_fetch_rejected = True
            return None
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", fetch)
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and "rejected" in msg and ioc_manager.refresh_refused(str(tmp_path))

    def test_update_oversize_or_nonjson_feed_marks_refused(self, tmp_path, monkeypatch):
        _write_signed_cache(str(tmp_path), {"version": "g", "malicious_domains": []})
        def fetch_remote(*a, **k):
            ioc_manager._last_fetch_rejected = True
            return (None, None)
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", fetch_remote)
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and "rejected" in msg and ioc_manager.refresh_refused(str(tmp_path))

    def test_plain_network_failure_still_unmarked(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (None, None))
        ok, msg = ioc_manager.update_iocs(cache_dir=str(tmp_path))
        assert not ok and not ioc_manager.refresh_refused(str(tmp_path))

    def test_real_nonjson_feed_sets_rejected(self, monkeypatch):
        self._urlopen(monkeypatch, b"<html>not json</html>")
        assert ioc_manager.fetch_remote_iocs("https://x/y", _return_raw=True) == (None, None)
        assert ioc_manager._last_fetch_rejected is True


class TestV8RedirectPinAndWarnings:
    @pytest.fixture(autouse=True)
    def _key(self, monkeypatch):
        monkeypatch.setattr(ioc_manager, "IOC_FEED_PUBKEY_HEX", _IOC_TEST_PUB.hex())

    def _handler(self):
        import urllib.request
        op = ioc_manager._pinned_opener()
        return [h for h in op.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
                and type(h) is not urllib.request.HTTPRedirectHandler][0]

    @pytest.mark.parametrize("target", [
        "http://raw.githubusercontent.com/x", "https://outside.example/feed",
        "file:///etc/passwd", "ftp://raw.githubusercontent.com/x",
        "https://raw.githubusercontent.com.evil.example/x"])
    def test_redirect_off_pin_refused_and_flagged(self, target):
        import urllib.request, urllib.error
        h = self._handler()
        req = urllib.request.Request("https://raw.githubusercontent.com/a")
        ioc_manager._last_fetch_rejected = False
        with pytest.raises(urllib.error.URLError):
            h.redirect_request(req, None, 302, "Found", {}, target)
        assert ioc_manager._last_fetch_rejected is True

    def test_redirect_within_allowlist_still_followed(self):
        import urllib.request
        h = self._handler()
        req = urllib.request.Request("https://raw.githubusercontent.com/a")
        new = h.redirect_request(req, None, 302, "Found", {}, "https://raw.githubusercontent.com/b")
        assert new is not None and new.full_url.endswith("/b")

    def test_redirect_refusal_is_exit_1_in_live_verify_and_update(self, tmp_path, monkeypatch):
        import urllib.request, urllib.error
        def opener_open(self, req, timeout=None):
            ioc_manager._last_fetch_rejected = True
            raise urllib.error.URLError("redirect refused")
        # simulate the handler firing mid-open: flag set, then URLError raised
        def fake_open(self, req, timeout=None):
            h = TestV8RedirectPinAndWarnings._handler(TestV8RedirectPinAndWarnings())
            h.redirect_request(req, None, 302, "F", {}, "https://outside.example/f")
        monkeypatch.setattr(urllib.request.OpenerDirector, "open", fake_open)
        code, res = ioc_manager.verify_live_feed((("latest.json", "https://raw.githubusercontent.com/a"),))
        assert code == 1

    def test_flags_reset_on_entry_even_for_rejected_url(self, monkeypatch):
        monkeypatch.setattr(ioc_manager, "_last_fetch_absent", True)
        monkeypatch.setattr(ioc_manager, "_last_fetch_rejected", True)
        assert ioc_manager._fetch_url_bytes("http://insecure.example/x", 10) is None
        assert ioc_manager._last_fetch_absent is False
        assert ioc_manager._last_fetch_rejected is False

    def _refuse(self, tmp_path, monkeypatch):
        feed = {"version": "n", "c2_ips": ["1.1.1.1"], "malicious_domains": [],
                "malicious_npm_packages": [], "malicious_pypi_packages": []}
        raw = json.dumps(feed).encode()
        monkeypatch.setattr(ioc_manager, "fetch_remote_iocs", lambda *a, **k: (feed, raw))
        monkeypatch.setattr(ioc_manager, "_fetch_url_bytes", lambda *a, **k: b"x" * 64)
        ioc_manager.update_iocs(cache_dir=str(tmp_path))

    def test_pre_scan_warning_no_cache_does_not_claim_cache(self, tmp_path, monkeypatch, capsys):
        import pre_scan
        self._refuse(tmp_path, monkeypatch)   # no cache present at all
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_refresh_refused"] and not iocs["_ioc_cache_served"]
        pre_scan.check_ioc_packages(["left-pad"], iocs=iocs)
        err = capsys.readouterr().err
        assert "last verified cached feed" not in err
        assert "no verified cached feed is available" in err

    def test_pre_scan_warning_expired_cache_does_not_claim_cache(self, tmp_path, monkeypatch, capsys):
        import pre_scan
        _write_signed_cache(str(tmp_path), {"version": "g", "malicious_domains": []})
        old = time.time() - 72 * 3600
        os.utime(tmp_path / ioc_manager.CACHE_FILENAME, (old, old))
        self._refuse(tmp_path, monkeypatch)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert not iocs["_ioc_cache_served"]
        pre_scan.check_ioc_packages(["left-pad"], iocs=iocs)
        assert "last verified cached feed" not in capsys.readouterr().err

    def test_pre_scan_warning_served_cache_claims_cache(self, tmp_path, monkeypatch, capsys):
        import pre_scan
        _write_signed_cache(str(tmp_path), {"version": "g", "malicious_domains": []})
        self._refuse(tmp_path, monkeypatch)
        iocs = ioc_manager.get_iocs(cache_dir=str(tmp_path))
        assert iocs["_ioc_cache_served"]
        pre_scan.check_ioc_packages(["left-pad"], iocs=iocs)
        assert "last verified cached feed" in capsys.readouterr().err
