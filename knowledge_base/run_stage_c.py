"""
Stage c runner: dedupe + gate over out/normalized.jsonl -> out/gated.jsonl (+ out/dropped_stage_c.csv).

Rules (conservative, best-judgment):
  - DEDUPE: MinHash-LSH near-duplicates (actual Jaccard >= 0.90). Within a cluster keep the
    richest record (longest description+discussion, tie-break higher upvotes), drop the rest.
  - GATE: drop records with no usable content (is_thin AND no code block). Everything else kept,
    including Uncategorized records that still carry real content.
"""
from __future__ import annotations

import collections
import csv
import json
import os

from dedupe import find_duplicate_clusters

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
NORM = os.path.join(OUT, "normalized.jsonl")


def _int(x) -> int:
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return 0


def main() -> int:
    recs = [json.loads(l) for l in open(NORM, encoding="utf-8")]
    n = len(recs)

    texts = [f"{r['title']}\n{r['description']}\n{r['discussion']}" for r in recs]
    clusters = find_duplicate_clusters(texts, num_perm=64, bands=16, threshold=0.90)

    # group indices by cluster
    groups: dict[int, list[int]] = collections.defaultdict(list)
    for i, c in enumerate(clusters):
        groups[c].append(i)

    dropped = {}   # idx -> reason
    dup_clusters = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        dup_clusters += 1
        # keep the richest; drop the others
        def richness(i):
            r = recs[i]
            return (len(r["description"]) + len(r["discussion"]),
                    _int(r["metadata"].get("upvotes")),
                    -int(r["source_id"]) if r["source_id"].isdigit() else 0)
        keep = max(members, key=richness)
        for i in members:
            if i != keep:
                dropped[i] = f"duplicate_of:{recs[keep]['uid']}"

    # gate survivors
    gated_idx = []
    for i, r in enumerate(recs):
        if i in dropped:
            continue
        f = r["flags"]
        if f.get("is_thin") and not f.get("has_code"):
            dropped[i] = "thin_no_content"
            continue
        gated_idx.append(i)

    # write outputs
    with open(os.path.join(OUT, "gated.jsonl"), "w", encoding="utf-8") as fh:
        for i in gated_idx:
            fh.write(json.dumps(recs[i], ensure_ascii=False) + "\n")

    with open(os.path.join(OUT, "dropped_stage_c.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["uid", "reason", "weakness_label", "title"])
        for i, reason in sorted(dropped.items()):
            w.writerow([recs[i]["uid"], reason, recs[i]["weakness_label"], recs[i]["title"][:80]])

    reasons = collections.Counter(v.split(":")[0] for v in dropped.values())
    print("=" * 56)
    print("Stage c (Dedupe + gate) - run summary")
    print("=" * 56)
    print(f"input records       : {n}")
    print(f"near-dup clusters    : {dup_clusters}")
    print(f"dropped total        : {len(dropped)}")
    for k, v in reasons.most_common():
        print(f"    {v:6d}  {k}")
    print(f"kept -> gated.jsonl  : {len(gated_idx)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
