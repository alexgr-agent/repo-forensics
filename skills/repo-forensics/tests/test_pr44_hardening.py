r"""Regression tests for the PR #44 hardening pass.

Maps to overnight-2026-09-22/findings/pr-44.md:
  HIGH (a)  _logical_lines join/clip regression (payload past the 10k join cap)
  HIGH (b)  ReDoS-bounded SA-SH-022 and RD-CP-013
  HIGH (c)  over-broad kernel-rule severities re-graded + privilege-DROP carve-outs
  HIGH #3   global rule-id uniqueness (no collision with PR #47)
  MED       sandbox-marker split: CURSOR_SANDBOX (medium) vs cloud-IDE (low)
  LOW       continuation join gated to real-continuation langs, CRLF-safe, odd `\`
"""

import re
import time
import pytest

import forensics_core as core
import scan_sast
import rule_loader


def _ids(tmp_path, name, body):
    f = tmp_path / name
    f.write_text(body, newline="")
    return [(x.rule_id, x.severity) for x in scan_sast.scan_file(str(f), name)]


# --- HIGH (a): join/clip regression -----------------------------------------
class TestLogicalLinesRegression:
    def test_payload_past_join_cap_still_detected(self, tmp_path):
        # 45 continuation lines of 240 chars push the joined logical line past
        # MAX_LINE_LENGTH; the real payload sits on the final physical line. On
        # the unfixed PR the join was clipped and the payload vanished.
        pad = "".join('y = ["%s", \\\n' % ("a" * 240) for _ in range(45))
        body = "import os\n" + pad + 'os.system("unshare -Urn sh " + user)\n'
        ids = [rid for rid, _ in _ids(tmp_path, "reg.py", body)]
        assert "SA-PY-007" in ids, "payload past the 10k join cap must still be scanned"

    def test_split_token_still_joined(self, tmp_path):
        ids = [rid for rid, _ in _ids(tmp_path, "s.sh", "#!/bin/bash\nunshare \\\n-Urn sh\n")]
        assert "SA-SH-020" in ids

    def test_split_token_crlf(self, tmp_path):
        ids = [rid for rid, _ in _ids(tmp_path, "s.sh", "#!/bin/bash\nunshare \\\r\n-Urn sh\r\n")]
        assert "SA-SH-020" in ids

    def test_js_continuation_not_joined_attribution(self, tmp_path):
        # `\` at EOL is not a JS continuation; the finding must attribute to the
        # code line (2), not the preceding `//` comment line (1).
        hits = [x for x in scan_sast.scan_file(
            str(_w(tmp_path, "c.js", "// note \\\nrequire('child_process').exec(userInput)\n")), "c.js")
            if x.rule_id == "SA-JS-005"]
        assert hits and all(h.line == 2 for h in hits)


def _w(tmp_path, name, body):
    f = tmp_path / name
    f.write_text(body, newline="")
    return f


# --- HIGH (b): ReDoS bounds -------------------------------------------------
class TestReDoSBounds:
    def _regex(self, pack, rid):
        rule_loader._reset_pack_cache()
        return next(r.regex for r in rule_loader.load_pack(pack).all_rules if r.id == rid)

    def test_sa_sh_022_linear(self):
        rx = self._regex("sast", "SA-SH-022")
        evil = "echo " + "a;" * 4990 + " modprobe"
        t = time.time(); rx.search(evil[:10000]); dt = time.time() - t
        assert dt < 0.05, f"SA-SH-022 took {dt*1000:.0f}ms on a 10k adversarial line"

    def test_rd_cp_013_linear(self):
        rx = self._regex("runtime_dynamism", "RD-CP-013")
        evil = "if " * 3000 + " stat /x"
        t = time.time(); rx.search(evil[:10000]); dt = time.time() - t
        assert dt < 0.05, f"RD-CP-013 took {dt*1000:.0f}ms on a 10k adversarial line"


# --- HIGH (c): severities + privilege-DROP carve-outs -----------------------
class TestSeverityAndCarveOuts:
    KERNEL_RULES = ("SA-SH-020", "SA-SH-021", "SA-SH-023",
                    "SA-PY-025", "SA-PY-029", "SA-PY-030")

    def test_kernel_rules_not_critical(self):
        rule_loader._reset_pack_cache()
        by = {r.id: r for r in rule_loader.load_pack("sast").all_rules}
        for rid in self.KERNEL_RULES:
            assert by[rid].severity == "high", f"{rid} should be high, not critical"

    def test_privilege_drop_idioms_not_flagged(self, tmp_path):
        # Standard container privilege DROP / hardening must be clean.
        assert not _ids(tmp_path, "a.sh",
                        'exec setpriv --reuid=app --regid=app --clear-groups --no-new-privs "$@"\n')
        assert not _ids(tmp_path, "b.sh", "capsh --drop=cap_sys_admin -- -c ./server\n")
        assert not _ids(tmp_path, "c.py", "libc.prctl(PR_CAPBSET_DROP, 19, 0, 0, 0)\n")

    def test_bare_word_in_prose_not_flagged(self, tmp_path):
        assert not _ids(tmp_path, "d.py", "MSG = 'we never pass CLONE_NEWUSER to unshare'\n")
        assert not _ids(tmp_path, "e.py", "DEPS = ['liburing', 'requests']\n")

    def test_real_escalations_still_fire(self, tmp_path):
        assert any(r == "SA-SH-023" for r, _ in _ids(tmp_path, "f.sh", "setpriv --reuid 0 bash\n"))
        assert any(r == "SA-PY-025" for r, _ in _ids(tmp_path, "g.py", "os.unshare(CLONE_NEWUSER)\n"))
        assert any(r == "SA-PY-030" for r, _ in _ids(tmp_path, "h.py", "libc.io_uring_setup(128, p)\n"))
        assert any(r == "SA-PY-029" for r, _ in _ids(tmp_path, "i.py", "capset(hdrp, datap)\n"))


# --- HIGH #3: global rule-id uniqueness -------------------------------------
class TestRuleIdUniqueness:
    def test_all_pack_rule_ids_globally_unique(self):
        rule_loader._reset_pack_cache()
        seen = {}
        for pack in ("secrets", "sast", "skill_threats", "mcp_security",
                     "shared", "runtime_dynamism"):
            for r in rule_loader.load_pack(pack).all_rules:
                assert r.id not in seen, (
                    f"rule id {r.id} used by both {seen.get(r.id)} and {pack}")
                seen[r.id] = pack


# --- MED: sandbox-marker severity split -------------------------------------
class TestSandboxMarkerSplit:
    def _run(self, tmp_path, name, body):
        import scan_runtime_dynamism
        f = tmp_path / name
        f.write_text(body, newline="")
        return [(x.rule_id, x.severity, x.category)
                for x in scan_runtime_dynamism.scan_file(str(f), name)]

    def test_cursor_sandbox_stays_medium(self, tmp_path):
        hits = [x for x in self._run(tmp_path, "a.py", "os.getenv('CURSOR_SANDBOX')\n")
                if "CURSOR_SANDBOX" in dict.fromkeys([x[0]]) or x[2] == "environment-detection"]
        got = self._run(tmp_path, "a2.py", "os.getenv('CURSOR_SANDBOX')\n")
        assert any(sev == "medium" and cat == "environment-detection" for _, sev, cat in got)

    def test_cloud_ide_marker_is_low(self, tmp_path):
        got = self._run(tmp_path, "b.js", "if (process.env.CODESPACES) { forwardPort(); }\n")
        cloud = [x for x in got if x[2] == "cloud-ide-detection"]
        assert cloud and all(sev == "low" for _, sev, _ in cloud)
