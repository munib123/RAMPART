"""
Stage d helper — section-based chunking.

One chunk per logical section (description / discussion / each code block); long sections are
split into overlapping windows on line boundaries. Every chunk carries the full CWE metadata so
ChromaDB can filter by cwe_id / severity / etc. at retrieval time. The report title is prepended
to each chunk as lightweight context.
"""
from __future__ import annotations

from typing import Iterator

MAX_CHARS = 1800      # ~ 450-500 tokens, well under gte-large-en-v1.5's 8k limit
OVERLAP = 200
MIN_CODE = 15         # ignore trivial code fragments


def split_text(text: str, max_chars: int = MAX_CHARS, overlap: int = OVERLAP) -> list[str]:
    """Greedy line-aware windowing with character overlap."""
    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]
    lines = text.split("\n")
    windows, cur = [], ""
    for ln in lines:
        # a single very long line -> hard-split it
        while len(ln) > max_chars:
            if cur:
                windows.append(cur.strip())
                cur = cur[-overlap:] if overlap else ""
            windows.append(ln[:max_chars])
            ln = ln[max_chars - overlap:]
        if len(cur) + len(ln) + 1 > max_chars:
            windows.append(cur.strip())
            cur = (cur[-overlap:] + "\n" + ln) if overlap else ln
        else:
            cur = (cur + "\n" + ln) if cur else ln
    if cur.strip():
        windows.append(cur.strip())
    return [w for w in windows if w.strip()]


def _meta(rec: dict) -> dict:
    m = rec.get("metadata", {})
    return {
        "uid": rec["uid"],
        "source": rec["source"],
        "source_id": rec["source_id"],
        "url": rec["url"],
        "title": rec["title"],
        "weakness_label": rec["weakness_label"],
        "cwe_id": rec["cwe_id"],
        "cwe_name": rec["cwe_name"],
        "cwe_category": rec["cwe_category"],
        "cwe_method": m.get("cwe_method", ""),
        "cwe_confidence": m.get("cwe_confidence", ""),
        "severity": rec["severity"],
        "has_fix": rec["has_fix"],
        "lang": rec["lang"],
        "program": m.get("program", ""),
    }


def chunk_record(rec: dict) -> Iterator[dict]:
    """Yield chunk dicts {chunk_id, text, embed_text, section_type, chunk_index, ...metadata}."""
    base = _meta(rec)
    title = rec["title"].strip()

    def emit(section: str, pieces: list[str]):
        for i, piece in enumerate(pieces):
            embed_text = f"{title}\n\n{piece}" if title and section != "title" else piece
            yield {
                **base,
                "chunk_id": f"{rec['uid']}#{section}#{i}",
                "section_type": section,
                "chunk_index": i,
                "text": piece,
                "embed_text": embed_text,
            }

    yield from emit("description", split_text(rec.get("description", "")))
    yield from emit("discussion", split_text(rec.get("discussion", "")))

    code_pieces = []
    for cb in rec.get("code_blocks", []):
        if len(cb.strip()) >= MIN_CODE:
            code_pieces.extend(split_text(cb))
    yield from emit("code", code_pieces)

    # guarantee at least one chunk (title-only) so a record is never lost from the index
    produced = (rec.get("description", "").strip() or rec.get("discussion", "").strip()
                or any(len(c.strip()) >= MIN_CODE for c in rec.get("code_blocks", [])))
    if not produced and title:
        yield from emit("title", [title])
