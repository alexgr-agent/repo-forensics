"""Every TOML string form pip accepts must still surface the dependency name."""

import pytest

import scan_manifest_drift as drift

BASIC_ML = '[project]\ndependencies = [\n  """hidden-dep>=1.0\n  """,\n]\n'
LITERAL_ML = "[project]\ndependencies = [\n  '''\nhidden-dep>=1.0\n''',\n]\n"
CONTINUATION = '[project]\ndependencies = [\n  """\\\n     hidden-dep>=1.0""",\n]\n'
LEADING_SPACE = '[project]\ndependencies = ["  hidden-dep>=1.0"]\n'
OPTIONAL_ML = '[project.optional-dependencies]\ndev = [\n  """hidden-dep\n""",\n]\n'
UNICODE_ESCAPE = '[project]\ndependencies = ["\\u0068idden-dep>=1"]\n'
BUILD_ML = '[build-system]\nrequires = ["""\nhidden-dep"""]\n'


@pytest.mark.parametrize("text", [
    BASIC_ML, LITERAL_ML, CONTINUATION, LEADING_SPACE, OPTIONAL_ML, BUILD_ML, UNICODE_ESCAPE,
], ids=["basic-multiline", "literal-multiline", "line-continuation",
        "leading-space", "optional-multiline", "build-multiline",
        "unicode-escape"])
def test_dependency_in_any_string_form_is_seen(text):
    assert "hidden_dep" in drift._parse_pyproject_dependencies(text)


def test_multiline_metadata_string_is_not_a_dependency():
    text = ('[project]\nname = "pkg"\ndescription = """\nrequests is great\n"""\n'
            'dependencies = ["real-dep"]\n')
    assert drift._parse_pyproject_dependencies(text) == {"real_dep"}


def test_multiline_string_does_not_end_the_array_early():
    text = '[project]\ndependencies = [\n  """a\n]""",\n  "b",\n]\n'
    assert {"a", "b"} <= drift._parse_pyproject_dependencies(text)


@pytest.mark.parametrize("text", [BASIC_ML, LITERAL_ML, CONTINUATION, LEADING_SPACE,
                                  OPTIONAL_ML, BUILD_ML, UNICODE_ESCAPE])
def test_fixtures_are_what_a_real_toml_parser_reads(text):
    tomllib = pytest.importorskip("tomllib")
    flat = repr(tomllib.loads(text))
    assert "hidden-dep" in flat


def test_hostile_quote_runs_stay_linear():
    import time
    for text in ['"' * 400000, '"""' * 130000, '"' + "\\" * 400000,
                 '[project]\ndependencies=["""' + '\\"""' * 100000 + '"""]']:
        start = time.process_time()
        drift._parse_pyproject_dependencies(text)
        assert time.process_time() - start < 2.0
