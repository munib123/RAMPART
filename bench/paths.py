"""Where the harness finds things. Everything is relative to the repo root, and the backend
package is put on sys.path so backends can import app.services.* without a separate install."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # <repo>
BENCH = ROOT / "bench"
KEYS = BENCH / "keys"
RUNS = BENCH / "runs"
TESTBEDS = ROOT / "testbeds"
BACKEND = ROOT / "backend"

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def key_file(benchmark: str) -> Path:
    p = KEYS / f"{benchmark}.key.jsonl"
    if not p.is_file():
        raise SystemExit(f"no answer key for benchmark '{benchmark}' at {p}")
    return p


def testbed_dir(benchmark: str) -> Path:
    p = TESTBEDS / benchmark
    if not p.is_dir():
        raise SystemExit(f"no testbed for benchmark '{benchmark}' at {p}")
    return p


def families_file() -> Path:
    return KEYS / "cwe_families.json"
