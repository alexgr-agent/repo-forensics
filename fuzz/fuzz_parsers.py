#!/usr/bin/env python3
"""Fuzz the parsers that read attacker-controlled files.

repo-forensics reads files from repos it has never seen. If a crafted file can
crash a parser or hang it, a malicious repo can silence that scanner. Each
target below must either return normally or raise the one error type its
contract allows. Anything else is a bug, and the fuzzer saves the input.

Run one target with Atheris (CI, Linux, Python 3.12):
    python3 fuzz/fuzz_parsers.py <target> -max_total_time=60 -timeout=10
Targets: capability_yaml, pyproject_deps, pnpm_lock, encoded_blobs

Without Atheris installed, the same harness runs a quick random smoke test:
    python3 fuzz/fuzz_parsers.py <target> --smoke 2000
"""

import os
import random
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "skills", "repo-forensics", "scripts"))

import forensics_core  # noqa: E402
import parse_pnpm_lock  # noqa: E402
import scan_decode  # noqa: E402
import scan_manifest_drift  # noqa: E402

try:
    import atheris
except ImportError:  # local smoke runs only; CI always has it
    atheris = None


def _text(data):
    return data.decode("utf-8", errors="replace")


def fuzz_capability_yaml(data):
    # Contract: returns a dict or raises ValueError for unsupported YAML.
    try:
        forensics_core._parse_capability_yaml(_text(data))
    except ValueError:
        pass


def fuzz_pyproject_deps(data):
    # Contract: never raises; returns the dependency names it could read.
    scan_manifest_drift._parse_pyproject_dependencies(_text(data))


_PNPM_DIR = tempfile.mkdtemp(prefix="rf-fuzz-pnpm-")
_PNPM_FILE = os.path.join(_PNPM_DIR, "pnpm-lock.yaml")


def fuzz_pnpm_lock(data):
    # Contract: never raises; corrupt files return an empty dict.
    with open(_PNPM_FILE, "wb") as fh:
        fh.write(data)
    result = parse_pnpm_lock.parse_pnpm_lock(_PNPM_FILE)
    if not isinstance(result, dict):
        raise AssertionError(f"expected dict, got {type(result).__name__}")


def fuzz_encoded_blobs(data):
    # Contract: detection and bounded decode-and-rescan never raise.
    text = _text(data)
    budget = scan_decode.new_budget()
    for blob in scan_decode.detect_encoded_blobs(text, floor=16)[:4]:
        scan_decode.rescan_blob(blob, "fuzz-input", budget=budget)


TARGETS = {
    "capability_yaml": fuzz_capability_yaml,
    "pyproject_deps": fuzz_pyproject_deps,
    "pnpm_lock": fuzz_pnpm_lock,
    "encoded_blobs": fuzz_encoded_blobs,
}

# Seeds give the mutator real structure to start from.
SEEDS = {
    "capability_yaml": b"capabilities:\n  - name: network\n    reason: fetches updates\n",
    "pyproject_deps": b'[project]\ndependencies = ["requests>=2", "rich"]\n'
                      b'[tool.poetry.dependencies]\npython = "^3.12"\nclick = "*"\n',
    "pnpm_lock": b"lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n"
                 b"    resolution: {integrity: sha512-abc}\n",
    "encoded_blobs": b'x = "cHJpbnQoJ2EgaGFybWxlc3Mgc2VlZCBmb3IgdGhlIGRlY29kZXIgZnV6emVyJyk="\n',
}


def _smoke(target, rounds):
    fn = TARGETS[target]
    rng = random.Random(1234)
    seed = SEEDS[target]
    for _ in range(rounds):
        data = bytearray(seed)
        for _ in range(rng.randint(1, 12)):
            op = rng.random()
            pos = rng.randint(0, len(data))
            if op < 0.4:
                data[pos:pos] = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 8)))
            elif op < 0.7 and data:
                del data[pos:pos + rng.randint(1, 8)]
            else:
                data[pos:pos] = seed[rng.randint(0, len(seed) - 1):][:rng.randint(1, 40)]
        fn(bytes(data))
    print(f"{target}: {rounds} random inputs, no crashes")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in TARGETS:
        sys.exit(f"usage: {sys.argv[0]} <{'|'.join(TARGETS)}> [atheris flags | --smoke N]")
    target = sys.argv[1]
    rest = sys.argv[2:]
    if rest[:1] == ["--smoke"] or atheris is None:
        _smoke(target, int(rest[1]) if len(rest) > 1 else 2000)
        return
    seed_dir = tempfile.mkdtemp(prefix=f"rf-fuzz-{target}-")
    with open(os.path.join(seed_dir, "seed"), "wb") as fh:
        fh.write(SEEDS[target])
    atheris.instrument_all()
    atheris.Setup([sys.argv[0]] + rest + [seed_dir], TARGETS[target])
    atheris.Fuzz()


if __name__ == "__main__":
    main()
