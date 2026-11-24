"""S1: the per-scan SliceCache in `services/extract.py`.

A scan usually has several findings in one file; re-reading and re-parsing it for every
finding was the largest avoidable cost in the extract phase. These tests pin the contract:
one read per unchanged file, invalidation after an edit, a bounded cache, and a line-window
fallback for non-Python (or unparsable) files.

Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_extract_cache.py -q
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import extract  # noqa: E402

PY_SOURCE = """\
def inner(request):
    return request.args["name"]


def outer(request):
    def nested():
        return request.args["name"]
    return nested()
"""


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def test_repeated_lookup_reads_the_file_once(tmp_path, monkeypatch):
    src = tmp_path / "app.py"
    _write(src, PY_SOURCE)

    reads = []
    real_read = extract._read

    def counting_read(path):
        reads.append(path)
        return real_read(path)

    monkeypatch.setattr(extract, "_read", counting_read)

    cache = extract.SliceCache()
    first = extract.extract_slice(str(src), 2, cache=cache)
    second = extract.extract_slice(str(src), 2, cache=cache)

    assert reads == [str(src)]
    assert first == second
    assert first["name"] == "inner"


def test_same_file_two_findings_reads_once_and_picks_innermost_function(tmp_path, monkeypatch):
    src = tmp_path / "app.py"
    _write(src, PY_SOURCE)

    reads = []
    real_read = extract._read
    monkeypatch.setattr(extract, "_read", lambda p: (reads.append(p), real_read(p))[1])

    cache = extract.SliceCache()
    inner = extract.extract_slice(str(src), 2, cache=cache)
    nested = extract.extract_slice(str(src), 6, cache=cache)

    assert reads == [str(src)]
    assert inner["name"] == "inner"
    assert nested["name"] == "nested"


def test_editing_the_file_invalidates_the_cache(tmp_path, monkeypatch):
    src = tmp_path / "app.py"
    _write(src, PY_SOURCE)

    reads = []
    real_read = extract._read
    monkeypatch.setattr(extract, "_read", lambda p: (reads.append(p), real_read(p))[1])

    cache = extract.SliceCache()
    extract.extract_slice(str(src), 2, cache=cache)

    _write(src, "def replacement():\n    return 1\n")
    st = os.stat(src)
    os.utime(src, (st.st_atime + 5, st.st_mtime + 5))

    changed = extract.extract_slice(str(src), 2, cache=cache)
    assert changed["name"] == "replacement"
    assert reads == [str(src), str(src)]


def test_cache_is_bounded_by_file_count(tmp_path):
    cache = extract.SliceCache(max_files=2)
    paths = []
    for i in range(3):
        p = tmp_path / f"f{i}.py"
        _write(p, f"def f{i}():\n    return {i}\n")
        paths.append(p)
        cache.get(str(p))
    assert len(cache) == 2

    # The most recent entries survive; the oldest was evicted.
    assert cache.get(str(paths[-1])) is not None
    assert len(cache) == 2


def test_oversized_file_is_returned_but_not_retained(tmp_path):
    src = tmp_path / "big.py"
    body = "x = 1\n" * 100
    _write(src, body)

    cache = extract.SliceCache(max_bytes=10)
    source, tree = cache.get(str(src))

    assert source == body
    assert tree is not None
    assert len(cache) == 0


def test_non_python_uses_a_line_window(tmp_path):
    src = tmp_path / "app.js"
    _write(src, "".join(f"line {i}\n" for i in range(1, 31)))

    out = extract.extract_slice(str(src), 15, cache=extract.SliceCache())

    assert out["name"] == ""
    assert out["start_line"] == 7
    assert out["end_line"] == 23
    assert out["code"].startswith("line 7\n")
    assert out["code"].endswith("line 23")


def test_unparsable_python_falls_back_to_the_window(tmp_path):
    src = tmp_path / "broken.py"
    _write(src, "".join(f"line {i}\n" for i in range(1, 21)) + "def broken(:\n")

    out = extract.extract_slice(str(src), 3, cache=extract.SliceCache())

    assert out["name"] == ""
    assert out["start_line"] == 1
    assert out["end_line"] == 11


def test_missing_file_returns_an_empty_slice(tmp_path):
    out = extract.extract_slice(str(tmp_path / "absent.py"), 4, cache=extract.SliceCache())
    assert out == {"code": "", "start_line": 4, "end_line": 4, "name": ""}
