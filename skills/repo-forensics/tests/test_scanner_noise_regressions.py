"""Regression tests for scanner noise on ordinary Python/web projects.

Each benign shape is paired with a twin that must keep firing.
"""

import os
import subprocess
import time

import pytest

import aggregate_json
import scan_manifest_drift as drift
import scan_sast
import scan_skill_threats
from shell_compat import sh_argv

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


def _pr010(tmp_path, content, rel=".github/workflows/release.yml"):
    f = tmp_path / "wf.yml"
    f.write_text(content)
    return [x for x in scan_skill_threats.scan_file(str(f), rel) if x.rule_id == "ST-PR-010"]


class TestWorkflowExpressions:
    def test_expressions_outside_run_are_low(self, tmp_path):
        hits = _pr010(tmp_path, (
            "name: Release\n"
            "concurrency:\n"
            "  group: ${{ github.workflow }}-${{ github.ref }}\n"
            "jobs:\n"
            "  build:\n"
            "    environment:\n"
            "      url: https://example.org/p/${{ needs.detect.outputs.version }}/\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          version: ${{ steps.detect.outputs.version }}\n"
            "      - name: Publish\n"
            "        env:\n"
            "          GH_TOKEN: ${{ github.token }}\n"
            "        run: echo done\n"))
        assert len(hits) == 4
        assert [h.severity for h in hits] == ["low", "high", "high", "high"]

    def test_expression_inside_run_block_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n  b:\n    steps:\n"
            "      - run: |\n"
            "          echo ${{ github.event.issue.title }}\n"))
        assert [h.severity for h in hits] == ["high"]

    def test_inline_run_and_github_script_stay_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n  b:\n    steps:\n"
            "      - run: echo ${{ github.head_ref }}\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: |\n"
            "            console.log('${{ github.event.comment.body }}')\n"))
        assert [h.severity for h in hits] == ["high", "high"]

    def test_untrusted_context_outside_run_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n  b:\n    steps:\n"
            "      - uses: some/action@v1\n"
            "        with:\n"
            "          title: ${{ github.event.pull_request.title }}\n"
            "          ref: ${{ github.head_ref }}\n"
            "          arg: ${{ inputs.cmd }}\n"))
        assert [h.severity for h in hits] == ["high", "high", "high"]

    def test_action_inputs_and_unknown_fields_stay_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: example/action@v1\n"
            "        with:\n"
            "          name: ${{ github.ref }}\n"
            "          arbitrary: ${{ github.ref }}\n"))
        assert len(hits) == 2
        assert [hit.severity for hit in hits] == ["high", "high"]

    def test_untrusted_context_hidden_in_function_or_index_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n  b:\n    steps:\n"
            "      - uses: some/action@v1\n"
            "        with:\n"
            "          a: ${{ format('{0}', github.event.issue.title) }}\n"
            "          b: ${{ github['event'].comment.body }}\n"
            "          c: ${{toJSON(github.event)}}\n"))
        assert [h.severity for h in hits] == ["high", "high", "high"]

    def test_issue_output_passed_through_env_to_eval_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "name: Issue handler\n"
            "on: issues\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        id: source\n"
            "        with:\n"
            "          script: |\n"
            "            core.setOutput('command', context.payload.issue.title)\n"
            "      - env:\n"
            "          COMMAND: ${{ steps.source.outputs.command }}\n"
            "        run: eval \"$COMMAND\"\n"))
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_flow_mapping_is_ambiguous_and_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            'jobs: {build: {runs-on: ubuntu-latest, steps: '
            '[{run: "echo ${{ github.ref }}"}]}}\n'))
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_quoted_run_key_is_ambiguous_and_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            '      - "run": echo ${{ github.ref }}\n'))
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_anchor_reused_as_script_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          options: &payload ${{ github.ref }}\n"
            "          script: *payload\n"))
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_run_body_over_200_lines_stays_high(self, tmp_path):
        body = "".join(f"          echo line {i}\n" for i in range(205))
        hits = _pr010(tmp_path, (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            + body +
            "          eval \"${{ steps.source.outputs.command }}\"\n"))
        assert len(hits) == 1
        assert hits[0].severity == "high"

        trusted = _pr010(tmp_path, (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            + body +
            "          echo ${{ github.ref }}\n"))
        assert len(trusted) == 1
        assert trusted[0].severity == "high"

    def test_output_and_env_contexts_in_allowed_fields_stay_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "name: ${{ env.WORKFLOW_NAME }}\n"
            "concurrency:\n"
            "  group: ${{ needs.build.outputs.group }}\n"
            "  cancel-in-progress: ${{ needs['build'].outputs['group'] }}\n"
            "jobs:\n"
            "  build:\n"
            "    name: ${{ env['WORKFLOW_NAME'] }}\n"
            "    steps:\n"
            "      - if: ${{ steps.source.outputs.enabled }}\n"
            "      - if: ${{ steps['source'].outputs['enabled'] }}\n"))
        assert len(hits) == 6
        assert [hit.severity for hit in hits] == ["high"] * 6

    def test_only_known_inert_workflow_fields_are_downgraded(self, tmp_path):
        hits = _pr010(tmp_path, (
            "name: ${{ github.ref }}\n"
            "concurrency:\n"
            "  group: ${{ github.ref }}\n"
            "jobs:\n"
            "  build:\n"
            "    if: ${{ github.ref }}\n"
            "    name: ${{ github.ref }}\n"
            "    concurrency: ${{ github.ref }}\n"
            "    runs-on: ${{ github.ref }}\n"
            "    timeout-minutes: ${{ github.ref }}\n"
            "    environment:\n"
            "      name: ${{ github.ref }}\n"
            "      url: https://example.test/${{ github.ref }}\n"
            "    steps:\n"
            "      - name: ${{ github.ref }}\n"
            "        if: ${{ github.ref }}\n"
            "        timeout-minutes: ${{ github.ref }}\n"))
        assert len(hits) == 12
        assert all(hit.severity == "low" for hit in hits)

    def test_many_workflow_expressions_keep_context_scan_linear(self, tmp_path):
        f = tmp_path / "many-expressions.yml"
        content = "".join(
            f"name: release-{i} ${{{{ github.ref }}}}\n" for i in range(12_000))
        f.write_text(content)

        start = time.process_time()
        hits = [hit for hit in scan_skill_threats.scan_file(
            str(f), ".github/workflows/release.yml") if hit.rule_id == "ST-PR-010"]
        cpu_seconds = time.process_time() - start

        assert len(hits) == 12_000
        assert cpu_seconds < 2.0, f"scanning 12,000 expressions used {cpu_seconds:.3f} CPU seconds"

    def test_environment_sibling_after_run_stays_high(self, tmp_path):
        hits = _pr010(tmp_path, (
            "jobs:\n  b:\n    steps:\n"
            "      - run: |\n"
            "          echo ok\n"
            "        env:\n"
            "          X: ${{ secrets.TOKEN }}\n"))
        assert [h.severity for h in hits] == ["high"]


class TestCssZeroSize:
    @pytest.mark.parametrize("decl", ["0.8125rem", "0.5em", "0.1px", "10px", "1rem"])
    def test_nonzero_sizes_are_not_zero_size_text(self, tmp_path, decl):
        f = tmp_path / "a.html"
        f.write_text("<style>p { font-size: %s; }</style>\n" % decl)
        titles = [x.title for x in scan_sast.scan_css_steganography(str(f), "a.html")]
        assert "CSS hiding: zero-size text" not in titles

    @pytest.mark.parametrize("decl", ["0", "0px", "0.0", "0rem", "0.00em", "0 !important", "0.01px", ".05em", "0.001rem"])
    def test_zero_sizes_still_flagged(self, tmp_path, decl):
        f = tmp_path / "a.html"
        f.write_text("<style>p { font-size: %s; }</style>\n" % decl)
        titles = [x.title for x in scan_sast.scan_css_steganography(str(f), "a.html")]
        assert "CSS hiding: zero-size text" in titles


PYPROJECT = '''[build-system]
requires = ["hatchling>=1.27"]
build-backend = "hatchling.build"

[project]
name = "demo-pkg"
license = "MIT"
description = "Local daemon for web services"
keywords = ["widget", "web-services"]
dependencies = [
    "aiohttp>=3.11",
    "example-lib>=7.12,<8",  # "commented"
]

[project.optional-dependencies]
extra = ["rich"]

[dependency-groups]
dev = ["pytest>=8", { include-group = "lint" }]
lint = ["ruff"]

[project.urls]
Repository = "https://example.org/tree/main/apps/demo"
'''


class TestPyprojectDependencies:
    def test_only_dependency_arrays_are_declared(self):
        assert drift._parse_pyproject_dependencies(PYPROJECT) == {
            "aiohttp", "example_lib", "rich", "pytest", "ruff", "hatchling"}

    def test_tool_level_dependency_arrays(self):
        text = ('[tool.uv]\ndev-dependencies = ["pytest>=8"]\n'
                '[tool.hatch.envs.default]\ndependencies = [\n  "coverage",\n]\n'
                '[project]\ndynamic = ["dependencies"]\nkeywords = ["notadep"]\n')
        assert drift._parse_pyproject_dependencies(text) == {"pytest", "coverage"}

    def test_empty_and_single_line_arrays(self):
        text = '[project]\ndependencies = []\nname = "x"\n[dependency-groups]\ndev = ["a", "b"]\n'
        assert drift._parse_pyproject_dependencies(text) == {"a", "b"}

    def test_brackets_inside_marker_strings_do_not_unbalance_arrays(self):
        text = ('[project]\ndependencies = [\n  "a; extra == \'[x\'",\n  "b",\n]\n'
                'name = "c"\n')
        assert drift._parse_pyproject_dependencies(text) == {"a", "b"}

    def test_poetry_tables(self):
        text = '[tool.poetry.dependencies]\npython = "^3.9"\nFlask-Cors = "^4"\n'
        assert drift._parse_pyproject_dependencies(text) == {"flask_cors"}

    def test_metadata_words_are_not_reported_unused(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(PYPROJECT)
        (tmp_path / "app.py").write_text("import aiohttp\nimport rich\n")
        unused = {f.title for f in drift.scan_manifest_drift(str(tmp_path))
                  if f.title.startswith("Declared but Unused")}
        assert not any(w in t for t in unused for w in ("mit", "widget", "web_services",
                                                         "demo_pkg", "hatchling", "tests", "src"))

    def test_build_requirement_imported_by_setup_py_is_declared(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["setuptools>=61", "wheel"]\n')
        (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n")
        titles = [f.title for f in drift.scan_manifest_drift(str(tmp_path))]
        assert not any("setuptools" in t for t in titles)

    def test_undeclared_import_still_phantom(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(PYPROJECT)
        (tmp_path / "app.py").write_text("import aiohttp\nimport mystery_pkg\n")
        titles = [f.title for f in drift.scan_manifest_drift(str(tmp_path))]
        assert any("mystery_pkg" in t for t in titles)

    def test_declared_unused_still_reported(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(PYPROJECT)
        (tmp_path / "app.py").write_text("import aiohttp\n")
        titles = [f.title for f in drift.scan_manifest_drift(str(tmp_path))]
        assert any("rich" in t for t in titles)


class TestEnrichmentGaps:
    def test_text_report_names_capability_gap(self):
        report = {
            "target": "x", "mode": "full", "scanner_count": 0, "scanners": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "verdicts": {}, "exit_code": 0, "findings": [],
            "enrichment_status": {
                "overall": "DEGRADED", "vulns": "complete", "rulepack_feed": "ok",
                "dead_anchors": "complete", "adjudication": "available",
                "adjudication_annotations": [],
                "capability_gaps": [{"scanner": "yara", "reason": "missing-tool",
                                     "category": "capability"}]},
        }
        text = aggregate_json.format_report_as_text(report)
        assert "capability_gaps: yara (missing-tool)" in text

    def test_no_gap_line_when_complete(self):
        report = {
            "target": "x", "mode": "full", "scanner_count": 0, "scanners": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "verdicts": {}, "exit_code": 0, "findings": [],
            "enrichment_status": {
                "overall": "COMPLETE", "vulns": "complete", "rulepack_feed": "ok",
                "dead_anchors": "complete", "adjudication": "available",
                "adjudication_annotations": [], "capability_gaps": []},
        }
        assert "capability_gaps" not in aggregate_json.format_report_as_text(report)


class TestUnknownUpdateFlag:
    def test_skip_update_is_rejected_with_a_hint(self, tmp_path):
        result = subprocess.run(
            sh_argv(os.path.join(SCRIPTS, "run_forensics.sh"), str(tmp_path), "--skip-update"),
            capture_output=True, text=True, check=False)
        assert result.returncode == 1
        assert "Unknown arg: --skip-update" in result.stdout
        assert "--offline" in result.stdout
