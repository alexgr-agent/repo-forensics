"""Latency ceiling for the Cursor blocking path — PRD v3 §5.6 row 7 (O7). P1.

beforeShellExecution sits in the agent's inner loop: every shell command waits
on it. A gate that is merely correct but slow gets uninstalled, so the budget
is a contract, not an aspiration.

MEASURED at M0 on the reference machine (Python 3.10, warm page cache), whole
process including interpreter startup:

    clean command (no finding)   median 18.3 ms   p95 26.9 ms
    IOC path (loads the feed)    median 24.8 ms   p95 32.0 ms
    in-process decision only     median  0.003 ms

Almost all of the wall time is `python` starting up, which is why the shipped
"<10ms" figure refers to the detection itself and is met with three orders of
magnitude to spare.

Ceilings below are set well above the reference numbers on purpose. This is a
regression alarm, not a benchmark: shared CI runners are routinely 3-5x slower
and vary run to run, and a test that fails on a noisy neighbour teaches people
to rerun until green. What it must catch is a change that puts real work on
this path — an unbounded subprocess spawn, a scanner import, a network call — which would
blow past these numbers by an order of magnitude, not a few milliseconds.

Methodology follows the eval review's flakiness note: discard warmup runs, take
N samples, assert on the MEDIAN (a single p95 sample on shared CI is a coin
flip), and carry a relative check that is immune to how slow the host is.
"""

import json
import os
import statistics
import time
from pathlib import Path

import cursor_helpers as ch
import pytest

WARMUP = 3
SAMPLES = 15

# Absolute ceilings (milliseconds, whole process incl. interpreter startup).
#
# Scaled on Windows, and not by a guess: this repo already carries a Windows-only
# CI failure of exactly this kind -- test_session_scan.py::TestLatency asserts
# `< 300ms` and measured 453ms on a shared windows-latest runner while ubuntu and
# macOS passed. Python process startup there is several times the POSIX cost
# before any of our code runs, and a shared runner adds variance on top.
#
# Adding a Windows job (this PR does) while keeping POSIX-tuned wall-clock
# assertions would import that same flake into a second workflow. The absolute
# numbers are a coarse "did someone put real work on this path" alarm; the guard
# that actually has teeth is the host-independent ratio check below, plus the
# structural invariants in TestBlockingPathDoesNoRealWork.
_WINDOWS = os.name == "nt"
_SCALE = 4 if _WINDOWS else 1

CLEAN_MEDIAN_CEILING_MS = 400 * _SCALE
IOC_MEDIAN_CEILING_MS = 600 * _SCALE

# The Cursor adapter must not cost meaningfully more than the Claude one: they
# run the same detector behind the same interpreter, so any real gap is the
# adapter doing work it should not. Host-speed independent.
ADAPTER_OVERHEAD_RATIO = 2.5


def _sample(fn, warmup=WARMUP, samples=SAMPLES):
    for _ in range(warmup):
        fn()
    timings = []
    for _ in range(samples):
        start = time.perf_counter()
        fn()
        timings.append((time.perf_counter() - start) * 1000.0)
    return timings


def _report(name, timings):
    return (f"{name}: median={statistics.median(timings):.1f}ms "
            f"min={min(timings):.1f}ms max={max(timings):.1f}ms n={len(timings)}")


class TestBlockingPathLatency:
    def test_clean_command_median_under_ceiling(self):
        timings = _sample(lambda: ch.run_cursor(ch.make_cursor_stdin("git status")))
        median = statistics.median(timings)
        assert median < CLEAN_MEDIAN_CEILING_MS, _report("clean", timings)

    def test_ioc_path_median_under_ceiling(self):
        """The IOC feed load is the slowest legitimate branch."""
        timings = _sample(lambda: ch.run_cursor(
            ch.make_cursor_stdin("npm install keyv@6.0.0")))
        median = statistics.median(timings)
        assert median < IOC_MEDIAN_CEILING_MS, _report("ioc", timings)

    def test_cursor_adapter_costs_no_more_than_claude(self):
        """Host-independent guard: same work, same wire, comparable cost."""
        cursor = statistics.median(_sample(
            lambda: ch.run_cursor(ch.make_cursor_stdin("git status"))))
        claude = statistics.median(_sample(
            lambda: ch.run_claude(ch.make_claude_stdin("git status"))))
        assert cursor < claude * ADAPTER_OVERHEAD_RATIO + 50, (
            f"cursor adapter overhead: cursor={cursor:.1f}ms claude={claude:.1f}ms")


class TestBlockingPathDoesNoRealWork:
    """The structural half of the budget. Timings drift with the host; these
    invariants are what actually keep the path fast, and they fail loudly the
    moment someone adds a scanner import or an unbounded subprocess to the gate."""

    def test_gate_inspects_without_spawning_a_process(self, monkeypatch):
        """Inspection stays in the hook process and never executes payloads."""
        import subprocess
        import sys
        import pre_scan
        raw = json.dumps(ch.make_cursor_stdin('echo benign'))
        def inspect(argv, **kwargs):
            pytest.fail('the gate must not spawn an inspection process')
        monkeypatch.setattr(pre_scan.hook_adapter, 'read_stdin', lambda **kw: raw)
        monkeypatch.setattr(sys, 'argv', [pre_scan.__file__, '--adapter', 'cursor'])
        monkeypatch.setattr(subprocess, 'run', inspect)
        with pytest.raises(SystemExit) as stopped:
            pre_scan.main()
        assert stopped.value.code == 0
        assert 'os.system' not in Path(pre_scan.__file__).read_text(encoding='utf-8')

    def test_hook_adapter_is_a_leaf_module(self):
        """hook_adapter must import nothing from the repo. If it grew a
        dependency on forensics_core, the blocking path would start paying for
        the whole scanner framework's import cost."""
        import hook_adapter
        source = Path(hook_adapter.__file__).read_text(encoding="utf-8")
        for forbidden in ("forensics_core", "rule_loader", "ioc_manager",
                          "auto_scan", "_shared_patterns", "_context_gate"):
            assert f"import {forbidden}" not in source, (
                f"hook_adapter must stay a leaf; it now imports {forbidden}")

    def test_in_process_decision_is_microseconds(self):
        """Excludes interpreter startup, which is the part we do not control."""
        import hook_adapter
        import pre_scan
        payload = json.dumps(ch.make_cursor_stdin("git status"))

        def once():
            request = hook_adapter.parse_request("cursor", payload)
            pre_scan.decide(request.command)

        timings = _sample(once, warmup=200, samples=2000)
        median = statistics.median(timings)
        assert median < 1.0, _report("in-process decision", timings)

    @pytest.mark.parametrize("cmd", ["git status", "echo hi", "ls -la"])
    def test_non_matching_commands_never_load_the_ioc_feed(self, cmd):
        """The fast path must stay fast: a command that matches no install
        pattern must not touch the IOC database at all."""
        import pre_scan
        loaded = []
        original = pre_scan.check_ioc_packages
        pre_scan.check_ioc_packages = lambda *a, **k: loaded.append(1) or []
        try:
            pre_scan.decide(cmd)
        finally:
            pre_scan.check_ioc_packages = original
        assert not loaded, f"{cmd!r} reached the IOC loader on the fast path"
