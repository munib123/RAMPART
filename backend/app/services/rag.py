"""
RAG retrieval over the knowledge base we built (ChromaDB + MiniLM-ONNX, no torch needed).

Queries the HackerOne + Nuclei collections, preferring a CWE-filtered match and falling back to
unfiltered semantic search, then merges the best exemplars across sources.
"""
from __future__ import annotations

import sys

from app import config

# Reuse the knowledge-base embedder + Chroma client (adds knowledge_base/ to the path).
sys.path.insert(0, str(config.KB_DIR))
from embed_store import make_embedder, get_collection  # noqa: E402

_embedder = None
_collections = None
_collection_errors: dict = {}


def _init():
    """Lazy: the embedder once; the collections until ALL of them are open. A collection that
    fails to open (Chroma's sqlite briefly locked by a process that is still exiting, a
    half-copied out/ directory) is retried on the next call instead of being silently dropped
    for the life of the process - before this, one transient failure at start-up meant every
    scan ran ungrounded and /api/health showed an empty list with no reason."""
    global _embedder, _collections
    if _embedder is None:
        _embedder = make_embedder("minilm-onnx")
    if _collections is not None and len(_collections) == len(config.COLLECTIONS):
        return
    opened = []
    for name in config.COLLECTIONS:
        try:
            opened.append(get_collection(name=name, persist_dir=str(config.CHROMA_DIR)))
            _collection_errors.pop(name, None)
        except Exception as e:
            _collection_errors[name] = f"{type(e).__name__}: {e}"
            print(f"[rag] collection {name} failed to open ({_collection_errors[name][:120]}); will retry")
    # keep the aligned (name, collection) pairs only when everything opened; otherwise expose
    # what did open and try the rest again next time
    _collections = opened


def _tolist(e):
    return e.tolist() if hasattr(e, "tolist") else [float(x) for x in e]


def retrieve(query_text: str, cwe_id: str = "", k: int = None) -> list[dict]:
    _init()
    k = k or config.RAG_K
    if not _collections:
        return []
    qv = _tolist(_embedder.encode([query_text])[0])
    hits = []
    for col in _collections:
        col_hits = 0   # per-collection, so one full collection cannot starve the others
        for where in ([{"cwe_id": cwe_id}] if cwe_id else []) + [None]:
            try:
                res = col.query(query_embeddings=[qv], n_results=k, where=where)
            except Exception:
                continue
            docs = res.get("documents", [[]])[0]
            metas = res.get("metadatas", [[]])[0]
            dists = res.get("distances", [[]])[0]
            for doc, md, dist in zip(docs, metas, dists):
                hits.append({
                    "uid": md.get("uid", ""),
                    "has_fix": bool(md.get("has_fix", False)),
                    "title": md.get("title", ""),
                    "cwe_id": md.get("cwe_id", ""),
                    "cwe_name": md.get("cwe_name", ""),
                    "severity": md.get("severity", ""),
                    "source": md.get("source", ""),
                    "section_type": md.get("section_type", ""),
                    "url": md.get("url", ""),
                    "sim": round(1 - float(dist), 3),
                    "text": (doc or "")[:600],
                })
                col_hits += 1
            if where is not None and col_hits >= k:
                break  # cwe-filtered gave enough for THIS collection; fallback not needed
    # dedupe by (title, section) keeping best sim, then top-k overall
    best = {}
    for h in hits:
        key = (h["uid"] or h["title"], h["section_type"])
        if key not in best or h["sim"] > best[key]["sim"]:
            best[key] = h
    return sorted(best.values(), key=lambda h: h["sim"], reverse=True)[:k]


def collection_stats() -> list[dict]:
    _init()
    by_name = {c.name: c for c in (_collections or [])}
    out = []
    for name in config.COLLECTIONS:            # every configured collection, in config order
        col = by_name.get(name)
        if col is None:
            out.append({"collection": name, "vectors": None, "error": _collection_errors.get(name, "not opened")})
            continue
        try:
            out.append({"collection": name, "vectors": col.count()})
        except Exception as e:
            out.append({"collection": name, "vectors": None, "error": f"{type(e).__name__}: {e}"})
    return out
