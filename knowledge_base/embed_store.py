"""
Stage d (part 2) — embed chunks with gte-large-en-v1.5 and store in a local ChromaDB collection.

Locked choices: Alibaba-NLP/gte-large-en-v1.5 (1024-dim, English) · ChromaDB persistent (local).
Every chunk keeps its CWE metadata so retrieval can filter by cwe_id / severity / category.
"""
from __future__ import annotations

import os
from typing import Iterable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
CHROMA_DIR = os.path.join(HERE, "out", "chroma")
MODEL_NAME = "Alibaba-NLP/gte-large-en-v1.5"
COLLECTION = "rampart_hackerone"

# Chroma metadata values must be str/int/float/bool (no None, no lists).
_META_KEYS = [
    "uid", "source", "source_id", "url", "title", "weakness_label",
    "cwe_id", "cwe_name", "cwe_category", "cwe_method", "cwe_confidence",
    "severity", "has_fix", "lang", "program", "section_type", "chunk_index",
]


def clean_metadata(ch: dict) -> dict:
    out = {}
    for k in _META_KEYS:
        v = ch.get(k, "")
        if v is None:
            v = ""
        if isinstance(v, (list, dict)):
            v = str(v)
        out[k] = v
    return out


class Embedder:
    """Real backend: gte-large-en-v1.5 via sentence-transformers (needs torch)."""
    dim = 1024

    def __init__(self, model_name: str = MODEL_NAME, device: Optional[str] = None):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name, trust_remote_code=True, device=device)

    def encode(self, texts: list[str], batch_size: int = 32):
        return self.model.encode(
            texts, batch_size=batch_size, normalize_embeddings=True,
            show_progress_bar=False, convert_to_numpy=True,
        )


class MiniLMEmbedder:
    """Torch-free validation backend: all-MiniLM-L6-v2 via chromadb's bundled ONNX runtime.

    Used only to smoke-test the chunk -> store -> filtered-query path when torch/gte can't run
    (e.g. this Store-Python box). NOT the production embedder (different model + 384 dims).
    """
    dim = 384

    def __init__(self):
        from chromadb.utils import embedding_functions as ef
        self.fn = ef.ONNXMiniLM_L6_V2()

    def encode(self, texts: list[str], batch_size: int = 256):
        out = []
        for i in range(0, len(texts), batch_size):
            out.extend(self.fn(texts[i:i + batch_size]))
        return out


def make_embedder(backend: str = "gte"):
    return MiniLMEmbedder() if backend == "minilm-onnx" else Embedder()


def get_collection(persist_dir: str = CHROMA_DIR, name: str = COLLECTION, reset: bool = False):
    import chromadb
    os.makedirs(persist_dir, exist_ok=True)
    client = chromadb.PersistentClient(path=persist_dir)
    if reset:
        try:
            client.delete_collection(name)
        except Exception:
            pass
    # cosine space; we pass our own (normalised) embeddings
    return client.get_or_create_collection(name, metadata={"hnsw:space": "cosine"})


def existing_ids(collection, page: int = 5000) -> set[str]:
    """All chunk ids already in the collection (ids only, no vectors/docs fetched)."""
    ids, offset = set(), 0
    while True:
        got = collection.get(include=[], limit=page, offset=offset).get("ids") or []
        ids.update(got)
        if len(got) < page:
            return ids
        offset += page


def embed_and_store(chunks: list[dict], embedder, collection, batch_size: int = 256,
                    log_every: int = 2000, skip_existing: bool = False) -> int:
    """Embed + add chunks. With skip_existing=True the call is idempotent and RESUMABLE: chunk
    ids already present are skipped, so an interrupted run can be continued without --reset and
    without hitting Chroma's duplicate-id error. Embeddings are deterministic (same model, same
    text), so a resumed collection is byte-identical to one built in a single pass."""
    import time
    if skip_existing:
        have = existing_ids(collection)
        before = len(chunks)
        chunks = [c for c in chunks if c["chunk_id"] not in have]
        print(f"  ... resume: {len(have)} already stored, {before - len(chunks)} skipped, "
              f"{len(chunks)} to embed", flush=True)
    added = 0
    t0 = time.time()
    next_log = log_every
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]
        embs = embedder.encode([c["embed_text"] for c in batch])
        collection.add(
            ids=[c["chunk_id"] for c in batch],
            embeddings=[(e.tolist() if hasattr(e, "tolist") else list(e)) for e in embs],
            documents=[c["text"] for c in batch],
            metadatas=[clean_metadata(c) for c in batch],
        )
        added += len(batch)
        if added >= next_log:
            rate = added / max(time.time() - t0, 1e-9)
            print(f"  ... {added}/{len(chunks)} embedded ({rate:.1f}/s)", flush=True)
            next_log += log_every
    return added
