"""
Stage b runner: adapter -> normalize -> normalized.jsonl (+ translation batches for non-English).

    python run_normalize.py

Writes:
    out/normalized.jsonl                    all 12,061 NormalizedRecords (pre-translation)
    <scratch>/tr_batches/tr_XXX.json        non-English records to translate (uid, title, description)
    out/translate_paths.json                the batch paths (for the translation workflow)
"""
from __future__ import annotations

import collections
import json
import os

from adapters import HackerOneAdapter, Normalizer

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
SCRATCH = r"C:\Users\symufolk\AppData\Local\Temp\claude\D--FYP\2b1acf67-66d2-4bcf-8c44-2c0072555e41\scratchpad"
TR_DIR = os.path.join(SCRATCH, "tr_batches")
TR_BATCH = 25
DESC_CAP = 4000  # cap per-field chars sent to the translator (keeps token cost bounded)


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(TR_DIR, exist_ok=True)
    for f in os.listdir(TR_DIR):
        os.remove(os.path.join(TR_DIR, f))

    ad = HackerOneAdapter()
    nz = Normalizer()

    total = 0
    with_cwe = thin = has_code = non_english = 0
    cats = collections.Counter()
    to_translate = []

    with open(os.path.join(OUT, "normalized.jsonl"), "w", encoding="utf-8") as fh:
        for rec in ad.iter_records():
            nr = nz.normalize(rec)
            total += 1
            with_cwe += 1 if nr.cwe_id else 0
            thin += 1 if nr.flags.get("is_thin") else 0
            has_code += 1 if nr.flags.get("has_code") else 0
            cats[nr.cwe_category or "(none)"] += 1
            if nr.lang != "en":
                non_english += 1
                to_translate.append({
                    "uid": nr.uid,
                    "title": nr.title[:400],
                    "description": nr.description[:DESC_CAP],
                })
            fh.write(nr.to_json() + "\n")

    # write translation batches
    paths = []
    for i in range(0, len(to_translate), TR_BATCH):
        p = os.path.join(TR_DIR, f"tr_{i // TR_BATCH:03d}.json")
        json.dump(to_translate[i:i + TR_BATCH], open(p, "w", encoding="utf-8"), ensure_ascii=False)
        paths.append(p.replace("\\", "/"))
    json.dump(paths, open(os.path.join(OUT, "translate_paths.json"), "w", encoding="utf-8"), indent=1)

    print("=" * 56)
    print("Stage b (Normalize) - run summary")
    print("=" * 56)
    print(f"normalized records : {total}")
    print(f"  with cwe_id      : {with_cwe}")
    print(f"  thin (b+d empty) : {thin}")
    print(f"  has code block   : {has_code}")
    print(f"  non-English      : {non_english}  -> {len(paths)} translation batches")
    print("category distribution:")
    for k, v in cats.most_common():
        print(f"  {v:6d}  {k}")
    print(f"\nwrote {os.path.join('out', 'normalized.jsonl')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
