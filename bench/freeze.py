"""
Freeze a testbed: record its tree hash so the held-out protocol is checkable, not just claimed.

    python -m bench.freeze djshop-dev --split dev
    python -m bench.freeze djshop-heldout --split held_out
    python -m bench.freeze --check                  # every frozen testbed still matches

Writes <testbed>/FREEZE.json = {benchmark, split, frozen_at, tree_sha256, files, note}. The
hash covers every file under the testbed except FREEZE.json itself (sorted relative paths +
bytes), so any later edit changes it. bench/tests/test_freeze.py fails on a mismatch, and
bench/run.py stamps tree_sha256 into every run artifact so a number can be tied to the exact
tree it was measured on. Re-freezing is a reviewed commit that bumps the key version.

Why: the Django vocabulary pack is authored from framework documentation AFTER the Django
testbed exists, and the held-out split is evaluated once. "Frozen before the pack existed" is
then a fact in git history (this file's commit precedes the pack's) plus a hash that has not
moved - rather than a sentence in the thesis.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from bench import paths

FREEZE = "FREEZE.json"
_SKIP_DIRS = {"__pycache__", ".git", ".venv", "node_modules"}


def tree_sha256(root: Path) -> tuple[str, int]:
    """sha256 over sorted (relative path, bytes) of every file except FREEZE.json."""
    h = hashlib.sha256()
    n = 0
    files = sorted(p for p in root.rglob("*")
                   if p.is_file() and p.name != FREEZE
                   and not any(part in _SKIP_DIRS for part in p.relative_to(root).parts))
    for p in files:
        rel = p.relative_to(root).as_posix()
        data = p.read_bytes().replace(b"\r\n", b"\n")       # line endings are not content
        h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(data).digest())
        n += 1
    return h.hexdigest(), n


def read(benchmark: str) -> dict | None:
    p = paths.TESTBEDS / benchmark / FREEZE
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def freeze(benchmark: str, split: str, note: str = "") -> dict:
    root = paths.testbed_dir(benchmark)
    sha, n = tree_sha256(root)
    doc = {"benchmark": benchmark, "split": split,
           "frozen_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "tree_sha256": sha, "files": n, "note": note}
    (root / FREEZE).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc


def check(benchmark: str) -> tuple[bool, str]:
    doc = read(benchmark)
    if doc is None:
        return True, "not frozen"
    sha, n = tree_sha256(paths.testbed_dir(benchmark))
    if sha != doc["tree_sha256"]:
        return False, f"tree changed since frozen_at {doc['frozen_at']}: {doc['tree_sha256'][:12]} -> {sha[:12]} ({n} files)"
    return True, f"frozen {doc['frozen_at']} ({doc['split']}, {n} files, {sha[:12]})"


def frozen_benchmarks() -> list[str]:
    return sorted(p.parent.name for p in paths.TESTBEDS.glob(f"*/{FREEZE}"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("benchmark", nargs="?")
    ap.add_argument("--split", choices=["dev", "held_out"], default="dev")
    ap.add_argument("--note", default="")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    if a.check:
        rc = 0
        for b in ([a.benchmark] if a.benchmark else frozen_benchmarks()):
            ok, why = check(b)
            print(f"[freeze] {b:<16} {'OK ' if ok else 'CHANGED'} {why}")
            rc = rc or (0 if ok else 1)
        return rc
    if not a.benchmark:
        ap.error("benchmark is required unless --check")
    doc = freeze(a.benchmark, a.split, a.note)
    print(f"[freeze] {a.benchmark}: {doc['files']} files, tree {doc['tree_sha256'][:12]}, split {doc['split']}, at {doc['frozen_at']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
