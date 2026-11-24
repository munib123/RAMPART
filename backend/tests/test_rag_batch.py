"""S1: batched, deduped RAG grounding in `services/rag.py`.

The real embedder/Chroma are replaced with fakes so these tests are about the batching
contract, not model quality: many findings -> ONE `encode()` call, repeated queries answered
from the bounded LRU, and results aligned with the input.

Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_rag_batch.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import rag  # noqa: E402


class FakeEmbedder:
    """Records every encode() batch and returns a stable one-dim vector per query."""

    def __init__(self):
        self.batches: list[list[str]] = []

    def encode(self, texts):
        batch = list(texts)
        self.batches.append(batch)
        return [[float(sum(map(ord, text)))] for text in batch]


class FakeCollection:
    def __init__(self, name: str = "rampart_test"):
        self.name = name
        self.queries: list = []

    def query(self, query_embeddings, n_results, where=None):
        vector = query_embeddings[0]
        self.queries.append(where)
        uid = str(int(vector[0]))
        return {
            "documents": [[f"doc-{uid}"]],
            "metadatas": [[{
                "uid": uid,
                "title": f"title-{uid}",
                "cwe_id": "CWE-79",
                "cwe_name": "XSS",
                "severity": "high",
                "source": "unit",
                "section_type": "description",
                "url": "",
                "has_fix": False,
            }]],
            "distances": [[0.1]],
        }


@pytest.fixture
def fakes(monkeypatch):
    rag._result_cache.clear()
    collection = FakeCollection()
    embedder = FakeEmbedder()
    monkeypatch.setattr(rag, "_init_collections", lambda: [collection])
    monkeypatch.setattr(rag, "_init_embedder", lambda: embedder)
    yield collection, embedder
    rag._result_cache.clear()


def _uid(query: str) -> str:
    return str(int(sum(map(ord, query))))


def test_many_findings_are_embedded_in_one_call(fakes):
    _, embedder = fakes
    items = [("query-a", "CWE-79")] * 10 + [("query-b", "CWE-89")] * 10

    results = rag.retrieve_many(items)

    assert len(results) == 20
    assert len(embedder.batches) == 1, "all unique queries must share one encode() call"
    assert sorted(embedder.batches[0]) == ["query-a", "query-b"]


def test_duplicate_findings_share_the_same_result(fakes):
    results = rag.retrieve_many([("query-a", "CWE-79")] * 5)
    assert all(r == results[0] for r in results)
    assert results[0][0]["uid"] == _uid("query-a")


def test_results_stay_aligned_with_the_input(fakes):
    queries = ["query-a", "query-b", "query-c"]
    results = rag.retrieve_many([(q, "CWE-79") for q in queries])

    assert [r[0]["uid"] for r in results] == [_uid(q) for q in queries]


def test_second_call_is_served_from_the_lru(fakes):
    _, embedder = fakes
    first = rag.retrieve_many([("query-a", "CWE-79"), ("query-b", "CWE-79")])
    second = rag.retrieve_many([("query-b", "CWE-79"), ("query-a", "CWE-79")])

    assert len(embedder.batches) == 1
    assert second[0] == first[1]
    assert second[1] == first[0]


def test_empty_input_does_no_work(fakes):
    _, embedder = fakes
    assert rag.retrieve_many([]) == []
    assert embedder.batches == []


def test_no_open_collections_returns_empty_lists(monkeypatch):
    monkeypatch.setattr(rag, "_init_collections", lambda: [])
    monkeypatch.setattr(rag, "_init_embedder", lambda: (_ for _ in ()).throw(AssertionError()))
    assert rag.retrieve_many([("query-a", "CWE-79")]) == [[]]


def test_cwe_and_k_are_part_of_the_cache_key(fakes):
    _, embedder = fakes
    rag.retrieve_many([("same-query", "CWE-79")])
    rag.retrieve_many([("same-query", "CWE-89")])
    rag.retrieve_many([("same-query", "CWE-79")], k=2)

    assert len(embedder.batches) == 3


def test_retrieve_wrapper_returns_the_single_result(fakes):
    assert rag.retrieve("query-a", "CWE-79")[0]["uid"] == _uid("query-a")


def test_collection_scope_change_forces_a_fresh_lookup(fakes, monkeypatch):
    collection, embedder = fakes
    rag.retrieve_many([("query-a", "CWE-79")])

    collection.name = "rampart_other"
    rag.retrieve_many([("query-a", "CWE-79")])

    assert len(embedder.batches) == 2
