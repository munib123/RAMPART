"""Extract the code slice around a finding: the containing function for Python (AST),
a line-window otherwise. Mirrors the approach in semgrep_test/extract_code.py."""
from __future__ import annotations

import ast

WINDOW = 8


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _python_function(source: str, line: int):
    try:
        tree = ast.parse(source)
    except SyntaxError:
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


def extract_slice(path: str, line: int) -> dict:
    """Return {code, start_line, end_line, name}."""
    try:
        source = _read(path)
    except OSError:
        return {"code": "", "start_line": line, "end_line": line, "name": ""}

    if path.endswith(".py"):
        fn = _python_function(source, line)
        if fn:
            return fn

    lines = source.splitlines()
    s = max(1, line - WINDOW)
    e = min(len(lines), line + WINDOW)
    return {"code": "\n".join(lines[s - 1:e]), "start_line": s, "end_line": e, "name": ""}
