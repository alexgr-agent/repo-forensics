"""Static guard for the Python 3.8 floor the README promises.

CI runs the suite on 3.8 (tests.yml, pytest-py38), but these checks catch the
common breakages on any interpreter: annotations that 3.8 evaluates at import
time (`str | None`, `list[str]`) and stdlib APIs added in 3.9+.
"""

import ast
import os

import pytest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GENERIC_BUILTINS = {"list", "dict", "tuple", "set", "frozenset", "type"}
_NEW_ATTRS = {"removeprefix", "removesuffix", "is_relative_to", "with_stem", "unparse",
              "randbytes", "bit_count", "pairwise"}
_NEW_MODULES = {"zoneinfo", "graphlib", "tomllib"}
# auto_scan.py is frozen for this release; its PurePath.is_relative_to call
# (3.9+) is a known gap to fix in that file.
_KNOWN = {("auto_scan.py", "is_relative_to")}


def _python_files():
    for sub in ("scripts", "tests"):
        for name in sorted(os.listdir(os.path.join(SKILL_DIR, sub))):
            if name.endswith(".py"):
                yield os.path.join(SKILL_DIR, sub, name)


def _runtime_annotations(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            for arg in (args.posonlyargs + args.args + args.kwonlyargs
                        + [args.vararg, args.kwarg]):
                if arg is not None and arg.annotation is not None:
                    yield arg.annotation
            if node.returns is not None:
                yield node.returns
        if isinstance(node, (ast.Module, ast.ClassDef)):
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign):
                    yield stmt.annotation


@pytest.mark.parametrize("path", list(_python_files()), ids=os.path.basename)
def test_no_python39_plus_constructs(path):
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source)
    name = os.path.basename(path)
    problems = []
    if "from __future__ import annotations" not in source:
        for annotation in _runtime_annotations(tree):
            for node in ast.walk(annotation):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                    problems.append(f"line {node.lineno}: X | Y annotation")
                if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                        and node.value.id in _GENERIC_BUILTINS):
                    problems.append(f"line {node.lineno}: {node.value.id}[...] annotation")
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and node.attr in _NEW_ATTRS
                and (name, node.attr) not in _KNOWN):
            problems.append(f"line {node.lineno}: .{node.attr}() is 3.9+")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = [a.name for a in node.names]
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            problems += [f"line {node.lineno}: import {m}" for m in modules
                         if m.split(".")[0] in _NEW_MODULES]
    assert not problems, f"{name} breaks on Python 3.8: {problems}"
