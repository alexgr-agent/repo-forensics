"""Plain code comments that tripped ST-SP-007 and ST-ST-002 (seen while vetting
an open-source fuzzing library). Real detections must still fire."""

import rule_loader
import scan_skill_threats as scanner


def _ids(tmp_path, name, text):
    f = tmp_path / name.replace("/", "_")
    f.write_text(text)
    return [x.rule_id for x in scanner.scan_file(str(f), name)]


class TestCredentialStoreRule:
    """Checked against the shipped pack only: a cached signed feed overlay on
    the test machine must not decide the result."""

    @staticmethod
    def _rule(tmp_path):
        pack = rule_loader.load_pack("skill_threats", cache_dir=str(tmp_path))
        return next(r for r in pack.all_rules if r.id == "ST-SP-007")

    def test_pass_show_keyword_argument_comment_is_not_a_credential_store(self, tmp_path):
        rule = self._rule(tmp_path)
        assert not rule.regex.search("# In 3.11, we need to pass show_caches=True.")
        assert not rule.regex.search("bypass showing the dialog")

    def test_password_store_lookup_still_fires(self, tmp_path):
        rule = self._rule(tmp_path)
        assert rule.regex.search("TOKEN=$(pass show github/token)")
        assert rule.regex.search("subprocess.run(['git-credential', 'fill'])")
        assert rule.regex.search("credential-store lookup")
