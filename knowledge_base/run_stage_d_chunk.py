"""
Stage d (part 1) runner: chunk out/gated.jsonl -> out/chunks.jsonl.
"""
from __future__ import annotations

import collections
import json
import os

from chunker import chunk_record

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
GATED = os.path.join(OUT, "gated.jsonl")


def main() -> int:
    recs = [json.loads(l) for l in open(GATED, encoding="utf-8")]
    n_chunks = 0
    per_section = collections.Counter()
    chunk_lens = []
    records_with_chunks = 0

    with open(os.path.join(OUT, "chunks.jsonl"), "w", encoding="utf-8") as fh:
        for r in recs:
            got = 0
            for ch in chunk_record(r):
                fh.write(json.dumps(ch, ensure_ascii=False) + "\n")
                per_section[ch["section_type"]] += 1
                chunk_lens.append(len(ch["embed_text"]))
                n_chunks += 1
                got += 1
            if got:
                records_with_chunks += 1

    chunk_lens.sort()
    med = chunk_lens[len(chunk_lens) // 2] if chunk_lens else 0
    print("=" * 56)
    print("Stage d.1 (Chunk) - run summary")
    print("=" * 56)
    print(f"gated records        : {len(recs)}")
    print(f"records with chunks  : {records_with_chunks}")
    print(f"total chunks         : {n_chunks}")
    print(f"chunks / record avg  : {n_chunks / max(1, len(recs)):.2f}")
    print(f"embed_text len median: {med}")
    print("chunks by section:")
    for k, v in per_section.most_common():
        print(f"    {v:7d}  {k}")
    print(f"\nwrote {os.path.join('out', 'chunks.jsonl')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
