"""
Stage d (part 2) runner: embed out/chunks.jsonl into a local ChromaDB collection.

    # production (needs torch + gte-large):
    python run_stage_d_embed.py --reset
    # torch-free smoke test of the store+query path (MiniLM/ONNX):
    python run_stage_d_embed.py --backend minilm-onnx --limit 3000 --reset
    # query:
    python run_stage_d_embed.py --backend minilm-onnx --query "SSRF via url parameter" --cwe CWE-918
"""
from __future__ import annotations

import argparse
import json
import os
import time

from embed_store import make_embedder, get_collection, embed_and_store, CHROMA_DIR

HERE = os.path.dirname(os.path.abspath(__file__))
CHUNKS = os.path.join(HERE, "out", "chunks.jsonl")

# gte = production (to build on GPU later); minilm = torch-free placeholder shipped now
COLL = {"gte": "rampart_hackerone", "minilm-onnx": "rampart_hackerone_minilm"}


def do_query(backend: str, text: str, cwe: str, k: int) -> None:
    emb = make_embedder(backend)
    col = get_collection(name=COLL[backend])
    q = emb.encode([text])[0]
    q = q.tolist() if hasattr(q, "tolist") else list(q)
    where = {"cwe_id": cwe} if cwe else None
    res = col.query(query_embeddings=[q], n_results=k, where=where)
    print(f"\nQuery: {text!r}" + (f"  [filter cwe_id={cwe}]" if cwe else "") + f"  (backend={backend})")
    for i, (doc, md, dist) in enumerate(zip(res["documents"][0], res["metadatas"][0], res["distances"][0])):
        print(f"\n#{i+1}  cos_sim={1-dist:.3f}  {md['cwe_id']} {md['cwe_name'][:38]}  [{md['section_type']}]")
        print(f"    {md['title'][:80]}")
        print(f"    {doc[:150].replace(chr(10),' ')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["gte", "minilm-onnx"], default="gte")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--query", type=str, default="")
    ap.add_argument("--cwe", type=str, default="")
    ap.add_argument("--k", type=int, default=5)
    args = ap.parse_args()

    if args.query:
        do_query(args.backend, args.query, args.cwe, args.k)
        return 0

    chunks = [json.loads(l) for l in open(CHUNKS, encoding="utf-8")]
    if args.limit:
        chunks = chunks[:args.limit]

    print(f"backend={args.backend}  loading model + chroma ...")
    t0 = time.time()
    emb = make_embedder(args.backend)
    col = get_collection(name=COLL[args.backend], reset=args.reset)
    print(f"  ready in {time.time()-t0:.1f}s. embedding {len(chunks)} chunks (dim={emb.dim}) ...")

    t1 = time.time()
    added = embed_and_store(chunks, emb, col)
    dt = time.time() - t1
    print(f"embedded + stored {added} chunks in {dt:.1f}s ({added/max(dt,1e-9):.1f} chunks/s)")
    print(f"collection '{COLL[args.backend]}' now has {col.count()} vectors at {CHROMA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
