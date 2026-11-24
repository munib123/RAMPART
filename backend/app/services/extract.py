"""Extract the code slice around a finding: the containing function for Python (AST),
a line-window otherwise. Mirrors the approach in semgrep_test/extract_code.py.

A scan usually has several findings in the same file, and re-reading/re-parsing that file for
every one of them was the single largest avoidable cost in the extract phase. `SliceCache` keeps
the source text and the parsed AST for one scan, keyed by (resolved path, mtime_ns, size): a
repeated lookup is a stat + dict hit, and editing the file changes the key, so a stale slice can
never be returned. The cache is bounded and cleared when the scan ends.
"""
from __future__ import annotations

import ast
import os
from collections import OrderedDict

WINDOW = 8

# Bounded per-scan cache: 256 files / 32 MB of source is far above a normal scan's hot set
# and small enough to never matter next to the RAG index.
MAX_FILES = 256
MAX_BYTES = 32 * 1024 * 1024

_UNSET = object()


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _python_function(source: str, line: int, tree=_UNSET):
    if tree is _UNSET:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
    if tree is None:                       # cached parse failure: do not parse again
        return None
    lines = source.splitlines()
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            if start <= line <= end:
                # keep the innermost (smallest) enclosing function
                if best is None or (end - start) < (best[1] - best[0]):
                    best = (start, end, node.name)
    if not best:
        return None
    s, e, name = best
    return {"code": "\n".join(lines[s - 1:e]), "start_line": s, "end_line": e, "name": name}


class SliceCache:
    """Source + AST cache for one scan. Keyed by resolved path, mtime_ns and size."""

    def __init__(self, max_files: int = MAX_FILES, max_bytes: int = MAX_BYTES):
        self.max_files = max_files
        self.max_bytes = max_bytes
        self._files: "OrderedDict[tuple[str, int, int], tuple[str, object, int]]" = OrderedDict()
        self._bytes = 0

    def get(self, path: str):
        """Return (source, ast-tree-or-None), or None when the file cannot be read."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        key = (os.path.realpath(path), st.st_mtime_ns, st.st_size)
        hit = self._files.get(key)
        if hit is not None:
            self._files.move_to_end(key)
            return hit[0], hit[1]

        try:
            source = _read(path)
        except OSError:
            return None

        tree = None
        if path.endswith(".py"):
            try:
                tree = ast.parse(source)
            except SyntaxError:
                tree = None

        # A single huge file is still read (the caller needs the slice) but not retained.
        if st.st_size <= self.max_bytes:
            self._files[key] = (source, tree, st.st_size)
            self._bytes += st.st_size
            self._evict()
        return source, tree

    def _evict(self) -> None:
        while self._files and (len(self._files) > self.max_files or self._bytes > self.max_bytes):
            _, (_, _, size) = self._files.popitem(last=False)
            self._bytes -= size

    def clear(self) -> None:
        self._files.clear()
        self._bytes = 0

    def __len__(self) -> int:
        return len(self._files)


def extract_slice(path: str, line: int, cache: SliceCache | None = None) -> dict:
    """Return {code, start_line, end_line, name}. Pass a per-scan `cache` to avoid re-reading
    and re-parsing a file that has several findings."""
    if cache is not None:
        hit = cache.get(path)
        if hit is None:
            return {"code": "", "start_line": line, "end_line": line, "name": ""}
        source, tree = hit
    else:
        try:
            source = _read(path)
        except OSError:
            return {"code": "", "start_line": line, "end_line": line, "name": ""}
        tree = _UNSET

    if path.endswith(".py"):
        fn = _python_function(source, line, tree)
        if fn:
            return fn

    lines = source.splitlines()
    s = max(1, line - WINDOW)
    e = min(len(lines), line + WINDOW)
    return {"code": "\n".join(lines[s - 1:e]), "start_line": s, "end_line": e, "name": ""}
