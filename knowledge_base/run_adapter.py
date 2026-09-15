"""
Exercise the HackerOne source adapter (Step 1) end-to-end over the real corpus.

Usage:
    python run_adapter.py                 # print a summary of all records
    python run_adapter.py --sample 20     # also dump 20 sample records to sample_records.jsonl
    python run_adapter.py --dump all.jsonl # stream every record to a JSONL file

Prints only ASCII-safe summary output (Windows console friendly).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

from adapters import HackerOneAdapter


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0, help="dump N sample records to sample_records.jsonl")
    ap.add_argument("--dump", type=str, default="", help="stream ALL records to this JSONL path")
    args = ap.parse_args()

    ad = HackerOneAdapter()
    here = os.path.dirname(os.path.abspath(__file__))

    total = 0
    thin = redaction = non_english = uncategorized = with_code = with_bounty = 0
    langs = collections.Counter()
    methods = collections.Counter()
    weaknesses = collections.Counter()
    body_lens = []
    samples = []

    dump_fh = open(os.path.join(here, args.dump), "w", encoding="utf-8") if args.dump else None
    try:
        for rec in ad.iter_records():
            total += 1
            f = rec.flags
            thin += bool(f.get("is_thin"))
            redaction += bool(f.get("has_redaction"))
            non_english += bool(f.get("is_non_english"))
            uncategorized += bool(f.get("is_uncategorized"))
            with_code += bool(rec.code_blocks)
            b = (rec.source_meta.get("bounty") or "0").strip()
            try:
                with_bounty += 1 if float(b) > 0 else 0
            except ValueError:
                pass
            langs[f.get("lang_guess", "?")] += 1
            methods[rec.source_meta.get("cwe_method", "?")] += 1
            weaknesses[rec.raw_weakness] += 1
            body_lens.append(len(rec.body))
            if args.sample and len(samples) < args.sample:
                samples.append(rec.to_dict())
            if dump_fh:
                dump_fh.write(rec.to_json() + "\n")
    finally:
        if dump_fh:
            dump_fh.close()

    body_lens.sort()
    med = body_lens[len(body_lens) // 2] if body_lens else 0

    print("=" * 60)
    print("HackerOne adapter - run summary")
    print("=" * 60)
    print(f"records emitted        : {total}")
    print(f"  thin (empty body)    : {thin}")
    print(f"  contain redaction    : {redaction}")
    print(f"  non-English (flagged): {non_english}")
    print(f"  Uncategorized        : {uncategorized}")
    print(f"  have code block(s)   : {with_code}")
    print(f"  paid a bounty (>0)   : {with_bounty}")
    print(f"  body length median   : {med}")
    print(f"distinct weakness labels: {len(weaknesses)}")
    print("\nlang_guess distribution:")
    for k, v in langs.most_common():
        print(f"  {v:6d}  {k}")
    print("\ncwe_method (labeling provenance) distribution:")
    for k, v in methods.most_common():
        print(f"  {v:6d}  {k}")
    print("\ntop 10 weakness labels:")
    for k, v in weaknesses.most_common(10):
        print(f"  {v:6d}  {k}")

    if args.sample and samples:
        out = os.path.join(here, "sample_records.jsonl")
        with open(out, "w", encoding="utf-8") as fh:
            for s in samples:
                fh.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"\nwrote {len(samples)} sample records -> {out}")
    if args.dump:
        print(f"streamed all records -> {os.path.join(here, args.dump)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
