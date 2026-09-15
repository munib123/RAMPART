"""
Run one arm against one benchmark, score it against the answer key, write a run artifact.

    python -m bench.run --backend joern --benchmark shopfast
    python -m bench.run --backend full  --benchmark shopfast --scanner bandit
    python -m bench.run --backend null  --benchmark shopfast          # the trivial baseline
    python -m bench.run --backend joern --benchmark shopfast --pack _base   # no_vocab_pack arm

Every run writes bench/runs/<utc-stamp>-<benchmark>-<backend>.json holding the backend
fingerprint, the key version and adjudication state, the score, and every candidate with its
outcome - so a number in the thesis can be traced to the exact rules, model, and key that
produced it. The answer key is re-resolved before scoring so a stale resolved_line can never
be scored.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time

from bench import freeze, paths
from bench.backends import get_backend
from bench.match import load_key, score
from bench.validate_key import validate


def run(backend_name: str, benchmark: str, scanner: str = "auto", quiet: bool = False,
        pack: str | None = None) -> dict:
    target = paths.testbed_dir(benchmark)
    validate(benchmark)                                   # re-resolve anchors; prints summary
    key = load_key(benchmark)
    kw: dict = {"scanner": scanner} if backend_name == "full" else {}
    if pack and backend_name in ("joern", "full"):
        kw["pack"] = pack
    backend = get_backend(backend_name, **kw)

    # Held-out protocol: a frozen testbed must still match its FREEZE.json (a changed tree is a
    # different benchmark), and every run of a held-out split is appended to heldout.log so a
    # second touch is on the record.
    frozen = freeze.read(benchmark)
    if frozen is not None:
        ok, why = freeze.check(benchmark)
        if not ok:
            raise SystemExit(f"[freeze] {benchmark}: {why}. Re-freeze in a reviewed commit or restore the tree.")

    t0 = time.time()
    cands = backend.locate(str(target))
    elapsed = time.time() - t0
    s = score(cands, key, target, verdict_gated=backend.verdict_gated)

    # P7: the finding's own route_reachable flag (meta.route) against the key row it matched.
    # Reported, never scored: the call graph is name-based and a file with no route markers
    # says "unknown" rather than guessing.
    by_no = {k.key_no: k for k in key}
    route_pairs = [(c.meta.get("route"), "yes" if by_no[c.matched_key].route_reachable else "no")
                   for c in cands if c.matched_key in by_no and c.meta.get("route")]
    known = [p for p in route_pairs if p[0] in ("yes", "no")]
    route_agreement = {"compared": len(known), "agree": sum(1 for g, w in known if g == w),
                       "unknown": sum(1 for g, _ in route_pairs if g == "unknown")}

    usable = [k for k in key if k.usable]
    result = {
        "run_id": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{benchmark}-{backend_name}"
                  + (f"-pack-{pack}" if pack else ""),
        "benchmark": benchmark,
        "backend": backend_name,
        "pack_arg": pack,
        "split": frozen["split"] if frozen else "dev",
        "tree_sha256": frozen["tree_sha256"] if frozen else None,
        "frozen_at": frozen["frozen_at"] if frozen else None,
        "verdict_gated": backend.verdict_gated,
        "elapsed_s": round(elapsed, 1),
        "fingerprint": backend.fingerprint(),
        "key": {
            "version": (key[0].raw.get("key_version") if key else None),
            "rows": len(key),
            "usable": len(usable),
            "accepted": sum(1 for k in usable if k.status == "accepted"),
            "proposed": sum(1 for k in usable if k.status != "accepted"),
        },
        "score": s.to_dict(),
        "route_agreement": route_agreement,
        "candidates": [c.to_dict() for c in cands],
    }
    paths.RUNS.mkdir(parents=True, exist_ok=True)
    out = paths.RUNS / f"{result['run_id']}.json"
    out.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    if frozen and frozen.get("split") == "held_out":
        sc = result["score"]
        with open(paths.RUNS / "heldout.log", "a", encoding="utf-8") as fh:
            fh.write(f"{result['run_id']}  tree={frozen['tree_sha256'][:12]}  backend={backend_name}"
                     f"  pack={pack or 'auto'}  tp={sc['tp']} fn={sc['fn']} fp={sc['fp']} bait={sc['bait_fp']} tn={sc['tn']}\n")

    if not quiet:
        _print(result, out)
    return result


def _print(r: dict, out) -> None:
    s = r["score"]
    pk = (r.get("fingerprint") or {}).get("pack") or {}
    tag = f"  pack {pk.get('tag')}" if isinstance(pk, dict) and pk.get("tag") else ""
    print(f"\n[run] {r['backend']} on {r['benchmark']}  ({r['elapsed_s']}s){tag}  -> {out.name}")
    print(f"      key {r['key']['version']}: {r['key']['usable']} usable rows "
          f"({r['key']['accepted']} accepted, {r['key']['proposed']} proposed, "
          f"{s['unresolvable_keys']} unresolvable)")
    print(f"      candidates {s['candidates']}  reported {s['reported']}")
    print(f"      TP {s['tp']}  FN {s['fn']}  FP {s['fp']}  bait_fp {s['bait_fp']}  "
          f"TN {s['tn']}  cleared {s['cleared']}")
    print(f"      recall {s['recall']}  reachable-recall {s['reachable_recall']}  "
          f"precision {s['precision']}  f1 {s['f1']}")
    ra = r.get("route_agreement") or {}
    if ra.get("compared") or ra.get("unknown"):
        print(f"      route flags: {ra['agree']}/{ra['compared']} agree with the key, {ra['unknown']} unknown")
    if s["matched_keys"]:
        print(f"      matched keys : {s['matched_keys']}")
    if s["missed_keys"]:
        print(f"      missed keys  : {s['missed_keys']}")
    bad = [c for c in r["candidates"] if c["outcome"] in ("fp", "bait_fp")]
    if bad:
        print("      false positives:")
        for c in bad:
            print(f"        {c['outcome']:8} {c['rel_path']}:{c['line']:<4} {c['function']:18} "
                  f"{c['cwe_id']:8} {c['rule_id']}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", required=True, help="null | bandit | semgrep | joern | full")
    ap.add_argument("--benchmark", default="shopfast")
    ap.add_argument("--scanner", default="auto", help="for --backend full: auto | bandit | semgrep")
    ap.add_argument("--pack", default=None,
                    help="vocabulary pack for the joern/full arms: auto | _base | flask-sqlite3 | <path.json>")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    run(a.backend, a.benchmark, a.scanner, a.quiet, a.pack)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
