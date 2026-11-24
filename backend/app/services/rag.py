"""
RAG retrieval over the knowledge base we built (ChromaDB + MiniLM-ONNX, no torch needed).

Queries the HackerOne + Nuclei + CrossVul collections, preferring a CWE-filtered match and
falling back to unfiltered semantic search, then merges the best exemplars across sources.

A scan asks for grounding once per verified finding, but those findings share many
(message, CWE) pairs. `retrieve_many()` dedupes them, embeds every unique query in ONE
`encode(list)` call, and keeps a bounded process-lifetime result cache, so a 60-finding scan
pays one embedder call instead of sixty.
"""
from __future__ import annotations

import hashlib
import sys
import threading
from collections import OrderedDict

from app import config

# Reuse the knowledge-base embedder + Chroma client (adds knowledge_base/ to the path).
sys.path.insert(0, str(config.KB_DIR))
from embed_store import make_embedder, get_collection  # noqa: E402

_embedder = None
_collections = None
_collection_errors: dict = {}

# Separate locks: warming the embedder (slow ONNX load) must not block collection stats.
_embedder_lock = threading.Lock()
_collections_lock = threading.Lock()

# Bounded LRU of query -> exemplars. Keyed by (cwe, k, query) so a different filter or top-k
# never reads another query's answer. A scan reuses hits for repeated findings.
_RESULT_CACHE_MAX = 2048
_result_cache: "OrderedDict[str, list[dict]]" = OrderedDict()
_result_lock = threading.Lock()


def _init_embedder():
    """Lazy, thread-safe: load the MiniLM-ONNX embedder once."""
    global _embedder
    if _embedder is None:
        with _embedder_lock:
            if _embedder is None:
                _embedder = make_embedder("minilm-onnx")
    return _embedder


def _init_collections():
    """Lazy: open every configured collection. A collection that fails to open (Chroma's
    sqlite briefly locked by a process that is still exiting, a half-copied out/ directory) is
    retried on the next call instead of being silently dropped for the life of the process -
    before this, one transient failure at start-up meant every scan ran ungrounded and
    /api/health showed an empty list with no reason.

    This deliberately does NOT touch the embedder: collection stats only need Chroma.
    """
    global _collections
    if _collections is not None and len(_collections) == len(config.COLLECTIONS):
        return _collections
    with _collections_lock:
        if _collections is not None and len(_collections) == len(config.COLLECTIONS):
            return _collections
        opened = []
        for name in config.COLLECTIONS:
            try:
                opened.append(get_collection(name=name, persist_dir=str(config.CHROMA_DIR)))
                _collection_errors.pop(name, None)
            except Exception as e:
                _collection_errors[name] = f"{type(e).__name__}: {e}"
                print(f"[rag] collection {name} failed to open ({_collection_errors[name][:120]}); will retry")
        # keep what did open and try the rest again next time
        _collections = opened
    return _collections


def _init():
    _init_embedder()
    _init_collections()


def warm() -> None:
    """Load the embedder + collections ahead of the first scan. Best-effort: a failure here is
    reported and retried on the first real request, never raised into app startup."""
    try:
        _init_embedder()
    except Exception as e:
        print(f"[rag] embedder warm-up skipped: {type(e).__name__}: {e}")
    try:
        _init_collections()
    except Exception as e:
        print(f"[rag] collection warm-up skipped: {type(e).__name__}: {e}")


def _tolist(e):
    return e.tolist() if hasattr(e, "tolist") else [float(x) for x in e]


def _cache_key(query_text: str, cwe_id: str, k: int, scope: str = "") -> str:
    return hashlib.sha1(f"{scope}\0{cwe_id}\0{k}\0{query_text}".encode("utf-8")).hexdigest()


def _pair(item) -> tuple[str, str]:
    """Accept (query, cwe) tuples or {"query"/"query_text", "cwe_id"} dicts."""
    if isinstance(item, dict):
        return (item.get("query") or item.get("query_text") or "",
                item.get("cwe_id") or "")
    query, cwe = item
    return query or "", cwe or ""


def _search(qv: list[float], cwe_id: str, k: int, collections: list) -> list[dict]:
    """Same collection/filter policy the single-query version always used."""
    hits = []
    for col in collections:
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


def retrieve_many(items, k: int | None = None) -> list[list[dict]]:
    """Ground many findings at once. `items` is a sequence of (query_text, cwe_id) pairs or
    dicts; the result is aligned with it. Unique queries are embedded in one encode() call;
    repeated queries are answered from a bounded process-lifetime LRU."""
    pairs = [_pair(item) for item in items]
    k = k or config.RAG_K
    if not pairs:
        return []

    collections = _init_collections()
    if not collections:
        return [[] for _ in pairs]

    # A result computed against a partial collection set must not be reused after more
    # collections open, so the cache key carries the exact set that answered it.
    scope = ",".join(getattr(c, "name", "") for c in collections)
    keys = [_cache_key(query, cwe, k, scope) for query, cwe in pairs]
    unique: "OrderedDict[str, tuple[str, str]]" = OrderedDict()
    for key, (query, cwe) in zip(keys, pairs):
        unique.setdefault(key, (query, cwe))

    with _result_lock:
        missing = [(key, query, cwe) for key, (query, cwe) in unique.items()
                   if key not in _result_cache]
    if missing:
        vectors = _init_embedder().encode([query for _, query, _ in missing])
        with _result_lock:
            for (key, _, cwe), vector in zip(missing, vectors):
                _result_cache[key] = _search(_tolist(vector), cwe, k, collections)
                _result_cache.move_to_end(key)
            while len(_result_cache) > _RESULT_CACHE_MAX:
                _result_cache.popitem(last=False)

    with _result_lock:
        return [list(_result_cache[key]) if key in _result_cache else [] for key in keys]


def retrieve(query_text: str, cwe_id: str = "", k: int | None = None) -> list[dict]:
    """Single-query wrapper kept for callers (and tests) that ground one finding at a time."""
    return retrieve_many([(query_text, cwe_id)], k=k)[0]


def collection_stats() -> list[dict]:
    collections = _init_collections()
    by_name = {c.name: c for c in (collections or [])}
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
