"""
Generic multi-source pipeline runner (stages b-e). Works for any registered source.

    python run_pipeline.py --source nuclei --stages normalize,gate,chunk
    python run_pipeline.py --source nuclei --stages embed --backend minilm-onnx --reset
    python run_pipeline.py --source nuclei --query "sql injection in id param" --cwe CWE-89

Stage a (the adapter) is supplied by sources.py; b-e reuse Normalizer / dedupe / chunker /
embed_store unchanged — this is the payoff of the pluggable-adapter design.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import os

from sources import get_source
from adapters import Normalizer
from dedupe import find_duplicate_clusters
from chunker import chunk_record
from embed_store import make_embedder, get_collection, embed_and_store


def _p(cfg, name):
    return os.path.join(cfg["outdir"], name)


def stage_normalize(cfg):
    ad = cfg["adapter"]()
    nz = Normalizer()
    total = with_cwe = thin = has_code = non_english = 0
    cats = collections.Counter(); sev = collections.Counter()
    with open(_p(cfg, "normalized.jsonl"), "w", encoding="utf-8") as fh:
        for rec in ad.iter_records():
            nr = nz.normalize(rec)
            total += 1
            with_cwe += 1 if nr.cwe_id else 0
            thin += 1 if nr.flags.get("is_thin") else 0
            has_code += 1 if nr.flags.get("has_code") else 0
            non_english += 1 if nr.lang != "en" else 0
            cats[nr.cwe_category or "(none)"] += 1
            sev[nr.severity] += 1
            fh.write(nr.to_json() + "\n")
    print(f"[normalize] {total} records | cwe_id {with_cwe} | thin {thin} | code {has_code} | non-en {non_english}")
    print(f"[normalize] severity {dict(sev)}")
    print(f"[normalize] category {dict(cats)}")
    if non_english:
        print(f"[normalize] NOTE: {non_english} non-English records — run translation before embed for best quality.")


def _int(x):
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return 0


def stage_gate(cfg):
    recs = [json.loads(l) for l in open(_p(cfg, "normalized.jsonl"), encoding="utf-8")]
    # Dedupe signature includes code. For HackerOne/Nuclei the prose dominates and the 800-token
    # shingle cap in dedupe.shingles() means appended code is never reached, so their behaviour is
    # unchanged. For a code-first source like CrossVul the description is only the CWE name and the
    # title only "<Class> in <language>", so prose alone collapses ~93% of the corpus into a few
    # clusters; the diff is the only thing that actually distinguishes two records.
    texts = [
        f"{r['title']}\n{r['description']}\n{r['discussion']}\n"
        + "\n".join(r.get("code_blocks") or [])
        for r in recs
    ]
    clusters = find_duplicate_clusters(texts, num_perm=64, bands=16, threshold=0.90)
    groups = collections.defaultdict(list)
    for i, c in enumerate(clusters):
        groups[c].append(i)
    dropped = {}
    dup_clusters = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        dup_clusters += 1
        keep = max(members, key=lambda i: (len(recs[i]["description"]) + len(recs[i]["discussion"])
                                           + sum(len(b) for b in (recs[i].get("code_blocks") or [])),
                                           _int(recs[i]["metadata"].get("upvotes"))))
        for i in members:
            if i != keep:
                dropped[i] = f"duplicate_of:{recs[keep]['uid']}"
    kept = []
    for i, r in enumerate(recs):
        if i in dropped:
            continue
        f = r["flags"]
        if f.get("is_thin") and not f.get("has_code"):
            dropped[i] = "thin_no_content"
            continue
        kept.append(i)
    with open(_p(cfg, "gated.jsonl"), "w", encoding="utf-8") as fh:
        for i in kept:
            fh.write(json.dumps(recs[i], ensure_ascii=False) + "\n")
    with open(_p(cfg, "dropped_stage_c.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh); w.writerow(["uid", "reason", "weakness_label", "title"])
        for i, reason in sorted(dropped.items()):
            w.writerow([recs[i]["uid"], reason, recs[i]["weakness_label"], recs[i]["title"][:80]])
    reasons = collections.Counter(v.split(":")[0] for v in dropped.values())
    print(f"[gate] input {len(recs)} | dup clusters {dup_clusters} | dropped {dict(reasons)} | kept {len(kept)}")


def stage_chunk(cfg):
    recs = [json.loads(l) for l in open(_p(cfg, "gated.jsonl"), encoding="utf-8")]
    n = 0; per = collections.Counter()
    with open(_p(cfg, "chunks.jsonl"), "w", encoding="utf-8") as fh:
        for r in recs:
            for ch in chunk_record(r):
                fh.write(json.dumps(ch, ensure_ascii=False) + "\n")
                per[ch["section_type"]] += 1; n += 1
    print(f"[chunk] {len(recs)} records -> {n} chunks | sections {dict(per)}")


def stage_embed(cfg, backend, reset):
    chunks = [json.loads(l) for l in open(_p(cfg, "chunks.jsonl"), encoding="utf-8")]
    coll = cfg["collection_minilm"] if backend == "minilm-onnx" else cfg["collection_gte"]
    emb = make_embedder(backend)
    col = get_collection(name=coll, reset=reset)
    print(f"[embed] backend={backend} dim={emb.dim} -> collection '{coll}', {len(chunks)} chunks ...")
    # Without --reset the stage resumes: chunks already in the collection are skipped, so an
    # interrupted embed can be continued and a completed one is a no-op rather than an error.
    added = embed_and_store(chunks, emb, col, skip_existing=not reset)
    print(f"[embed] stored {added} | collection now has {col.count()} vectors "
          f"(expected {len(chunks)})", flush=True)


def do_query(cfg, backend, text, cwe, k):
    coll = cfg["collection_minilm"] if backend == "minilm-onnx" else cfg["collection_gte"]
    emb = make_embedder(backend); col = get_collection(name=coll)
    q = emb.encode([text])[0]
    q = q.tolist() if hasattr(q, "tolist") else [float(x) for x in q]
    where = {"cwe_id": cwe} if cwe else None
    res = col.query(query_embeddings=[q], n_results=k, where=where)
    print(f"\nQuery {text!r}" + (f" [cwe_id={cwe}]" if cwe else "") + f"  ({coll})")
    for md, dist in zip(res["metadatas"][0], res["distances"][0]):
        print(f"  sim={1-dist:.3f} {md['cwe_id']:8} {md.get('severity',''):8} [{md['section_type']:11}] {md['title'][:52]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--stages", default="normalize,gate,chunk,embed")
    ap.add_argument("--backend", choices=["gte", "minilm-onnx"], default="minilm-onnx")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--query", default="")
    ap.add_argument("--cwe", default="")
    ap.add_argument("--k", type=int, default=5)
    args = ap.parse_args()
    cfg = get_source(args.source)

    if args.query:
        do_query(cfg, args.backend, args.query, args.cwe, args.k)
        return 0

    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    for s in stages:
        if s == "normalize": stage_normalize(cfg)
        elif s == "gate":    stage_gate(cfg)
        elif s == "chunk":   stage_chunk(cfg)
        elif s == "embed":   stage_embed(cfg, args.backend, args.reset)
        else:                raise SystemExit(f"unknown stage '{s}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
