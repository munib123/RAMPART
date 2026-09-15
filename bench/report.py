"""
Summarise bench/runs/*.json as a markdown table - the one that goes in the thesis.

    python -m bench.report                    # all runs
    python -m bench.report --benchmark shopfast --latest   # newest run per (backend, pack)
    python -m bench.report --latest --split held_out       # the once-only held-out numbers
"""
from __future__ import annotations

import argparse
import json
import sys

from bench import paths


def load_runs(benchmark: str | None) -> list[dict]:
    runs = []
    for p in sorted(paths.RUNS.glob("*.json")):
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if benchmark and r.get("benchmark") != benchmark:
            continue
        runs.append(r)
    return runs


def pack_of(r: dict) -> str:
    """The vocabulary pack a joern/full run used (P5+), '' for arms that have none."""
    fp = r.get("fingerprint") or {}
    pk = fp.get("pack")
    if isinstance(pk, dict) and pk.get("id"):
        return pk["id"]
    return r.get("pack_arg") or ""


def table(runs: list[dict]) -> str:
    def f(x):
        return "-" if x is None else (f"{x:.2f}" if isinstance(x, float) else str(x))
    hdr = ("| run | benchmark | backend | pack | key | TP | FN | FP | bait FP | TN | cleared | recall "
           "| reach. recall | precision | F1 | s |")
    sep = "|" + "---|" * 17
    rows = [hdr, sep]
    for r in runs:
        s = r["score"]; k = r["key"]
        keyinfo = f"{k['version']} ({k['accepted']}/{k['usable']} adj.)"
        rows.append(
            f"| {r['run_id'][:15]} | {r['benchmark']} | {r['backend']} | {pack_of(r) or '-'} | {keyinfo} "
            f"| {s['tp']} | {s['fn']} | {s['fp']} | {s['bait_fp']} | {s['tn']} | {s['cleared']} "
            f"| {f(s['recall'])} | {f(s['reachable_recall'])} | {f(s['precision'])} | {f(s['f1'])} | {f(r['elapsed_s'])} |")
    return "\n".join(rows)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benchmark", default=None)
    ap.add_argument("--latest", action="store_true", help="newest run per (benchmark, backend, pack)")
    ap.add_argument("--split", default=None, help="dev | held_out (runs on frozen testbeds carry it)")
    a = ap.parse_args(argv)
    runs = load_runs(a.benchmark)
    if a.split:
        runs = [r for r in runs if r.get("split") == a.split]
    if a.latest:
        latest: dict[tuple, dict] = {}
        for r in runs:
            latest[(r["benchmark"], r["backend"], pack_of(r))] = r
        runs = list(latest.values())
    if not runs:
        print("no runs found under", paths.RUNS); return 1
    print(table(runs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
