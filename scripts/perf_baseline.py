#!/usr/bin/env python
"""Record a RAMPART performance baseline (S0 of the optimization pass).

Measures, in-process (no server process, no browser):

  * cold and warm ``GET /api/health`` latency
  * full ``POST /api/scan`` wall time on the bundled targets, using bandit
    with the Joern phase off
  * the finding counts each scan produced

Gemini and the database are disabled for the run, so no API key and no
``DATABASE_URL`` are needed. The result is written to
``bench/runs/perf-baseline-<YYYY-MM-DD>.json`` (override with ``--out``).

Run from the repo root with the backend venv:

    backend\\.venv\\Scripts\\python.exe scripts\\perf_baseline.py
    backend\\.venv\\Scripts\\python.exe scripts\\perf_baseline.py --targets semgrep_test/test_code
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
DEFAULT_TARGETS = [
    ROOT / "semgrep_test" / "test_code",
    ROOT / "testbeds" / "shopfast",
]


def _disable_optional_services() -> None:
    """Must run before app.config is imported: config reads the environment once."""
    os.environ["GEMINI_API_KEY"] = ""
    os.environ["GEMINI_FALLBACK_MODELS"] = ""
    os.environ["DATABASE_URL"] = ""
    os.environ["JOERN_ENABLED"] = "off"
    os.environ["JOERN_SERVER"] = "off"


def _git_commit() -> str:
    try:
        p = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                           capture_output=True, text=True, timeout=15)
        return p.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _health(client, label: str) -> dict:
    t0 = time.perf_counter()
    try:
        r = client.get("/api/health")
        ms = (time.perf_counter() - t0) * 1000.0
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:400]}
        return {"sample": label, "status_code": r.status_code, "ms": round(ms, 2), "body": body}
    except Exception as e:
        return {"sample": label, "status_code": None,
                "ms": round((time.perf_counter() - t0) * 1000.0, 2),
                "error": f"{type(e).__name__}: {e}"}


def _scan(client, target: Path) -> dict:
    entry = {"target": _rel(target), "path": str(target)}
    if not target.exists():
        entry["error"] = "target does not exist"
        return entry
    t0 = time.perf_counter()
    try:
        r = client.post("/api/scan", json={"path": str(target), "scanner": "bandit"})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:400]}
        entry.update(
            status_code=r.status_code,
            elapsed_ms=round(elapsed_ms, 1),
            ok=bool(body.get("ok")),
            scanner=body.get("scanner"),
            counts=body.get("counts"),
            error=body.get("error"),
            llm=body.get("llm"),
            joern=body.get("joern"),
        )
    except Exception as e:
        entry.update(status_code=None,
                     elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 1),
                     ok=False, error=f"{type(e).__name__}: {e}")
    return entry


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", nargs="*", default=None,
                    help="targets to scan, relative to the repo root "
                         "(default: semgrep_test/test_code testbeds/shopfast)")
    ap.add_argument("--warm-samples", type=int, default=5,
                    help="warm /api/health samples after the cold call (default: 5)")
    ap.add_argument("--out", default=None,
                    help="output JSON path (default: bench/runs/perf-baseline-<date>.json)")
    ap.add_argument("--skip-scans", action="store_true", help="only measure /api/health")
    args = ap.parse_args(argv)

    _disable_optional_services()
    sys.path.insert(0, str(BACKEND))

    from fastapi.testclient import TestClient  # noqa: E402
    from app.main import app  # noqa: E402

    targets = ([ROOT / t for t in args.targets] if args.targets else DEFAULT_TARGETS)
    result: dict = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "git_commit": _git_commit(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "config": {
            "scanner": "bandit",
            "joern": "off",
            "llm": "off (GEMINI_API_KEY cleared)",
            "db": "off (DATABASE_URL cleared)",
        },
        "health": {},
        "scans": [],
    }

    with TestClient(app) as client:
        cold = _health(client, "cold")
        time.sleep(1.0)  # let the start-up warm-up thread settle before "warm"
        warm = [_health(client, f"warm-{i + 1}") for i in range(max(0, args.warm_samples))]
        warm_ms = [s["ms"] for s in warm if s.get("status_code") == 200]
        result["health"] = {
            "cold_ms": cold["ms"],
            "cold_status_code": cold["status_code"],
            "warm_samples_ms": warm_ms,
            "warm_p50_ms": round(statistics.median(warm_ms), 2) if warm_ms else None,
            "warm_p95_ms": _percentile(warm_ms, 95),
            "warm_max_ms": max(warm_ms) if warm_ms else None,
            "cold_body": cold.get("body"),
        }
        if not args.skip_scans:
            for target in targets:
                print(f"[perf] scanning {_rel(target)} ...", flush=True)
                entry = _scan(client, target)
                print(f"[perf]   {entry.get('elapsed_ms')} ms  ok={entry.get('ok')}  "
                      f"counts={entry.get('counts')}", flush=True)
                result["scans"].append(entry)

    out = Path(args.out) if args.out else (
        ROOT / "bench" / "runs" / f"perf-baseline-{dt.date.today().isoformat()}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print()
    print(f"[perf] health cold {result['health']['cold_ms']} ms, "
          f"warm p95 {result['health']['warm_p95_ms']} ms")
    for s in result["scans"]:
        print(f"[perf] scan {s['target']}: {s.get('elapsed_ms')} ms  "
              f"ok={s.get('ok')}  counts={s.get('counts')}")
    print(f"[perf] wrote {_rel(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
