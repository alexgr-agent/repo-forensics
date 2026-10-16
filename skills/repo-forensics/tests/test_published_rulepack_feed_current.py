"""The published rule-pack feed must never drop a rule the skill already ships.

If it does, every installed copy rejects the overlay for that scanner and runs
rule-pack-degraded until the feed is republished (scripts/sign_rulepacks.py).
"""

import os
import shutil

import pytest

import rule_loader

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
BUNDLE = os.path.join(REPO, "iocs", "rulepacks.json")
PACKS = sorted(f[:-5] for f in os.listdir(os.path.join(os.path.dirname(rule_loader.__file__), "..", "data", "rulepacks"))
               if f.endswith(".json"))


@pytest.mark.skipif(not os.path.exists(BUNDLE), reason="published feed lives in the repo, not the installed skill")
@pytest.mark.parametrize("scanner", PACKS)
def test_published_feed_overlays_cleanly(tmp_path, monkeypatch, scanner):
    shutil.copy(BUNDLE, tmp_path / "bundle.json")
    shutil.copy(BUNDLE + ".sig", tmp_path / "bundle.json.sig")
    monkeypatch.setattr(rule_loader, "CACHE_RULEPACK_DIR", str(tmp_path))
    rule_loader.load_pack(scanner)
    log = rule_loader.get_overlay_log()
    applied = [line for line in log if line.startswith(scanner + ": overlaid")]
    assert applied, (
        f"{log}: the published feed did not overlay {scanner}; republish it with "
        f"python3 scripts/sign_rulepacks.py --seed-file <offline-feed-seed-file>")
