"""
O3 re-verification (P8): after a fix, does the exploitable path still exist?

A pattern matcher can only say "the text pattern vanished". The CPG can say whether the
locator still fires on the patched method, and if it does not, WHY: a guard token now sits in
the method's guard channel (or on its class, or in a form it instantiates), or the sink itself
is gone. That distinction is the whole point - a fix that renames a variable makes no pattern
vanish and no guard appear, and it must not converge.

Two modes, one function:
  preview     verify(target, path, function, rule_id, fixed_code=..., start_line=..., end_line=...)
              copies the whole target into scratch, applies the fix THERE, rebuilds the CPG on
              the copy. The user's tree is untouched. The live tree is the "before" state.
  post-apply  verify(target, path, function, rule_id, before_dir=<snapshot tree>)
              rebuilds the CPG on the live (already patched) tree; the snapshot taken at first
              Apply is the "before" state, so regressions can still be diffed.

Convergence (TDD 8.9): the locator fired before, does not fire after, and the whole-target
re-scan added no new candidate anywhere (a fix that moves the bug is not a fix). The decision
is a pure function of the two scan results - decide() - so it is unit-tested without a JVM.

reverify_method is "cpg" when the graph answered, "pattern" when Joern is unavailable and the
only evidence is a token search over the patched function's code (strings and comments
blanked). The weaker answer is labelled.

The method is addressed as (relative file, class, method); `function` may be `Class.method`
as the UI's slice name spells it. All three are validated as identifiers / a relative .py path
before they go anywhere near the Scala, and escaped again when they do.
"""
from __future__ import annotations

import ast
import io
import shutil
import time
import tokenize
import uuid
from pathlib import Path
from typing import Optional

from app import config
from app.services import apply as apply_svc
from app.services.joern import runtime, scan as joern_scan
from app.services.joern.vocab import validate as vocab

# which guard family answers which rule, and which sink counts say "the sink is gone"
_RULE_GUARD = {
    "joern-idor-missing-ownership": ("authz", ("reads", "exec_reads")),
    "joern-mass-assignment": ("allowlist", ("dyn_writes", "exec_writes")),
    "joern-unchecked-quantity": ("positive", ("mult",)),
    "joern-toctou-check-then-write": ("lock", ("ctl_writes",)),
}
_RULE_SLOTS = {   # pack slots for the pattern fallback
    "joern-idor-missing-ownership": ["authz_guard"],
    "joern-mass-assignment": ["allowlist_guard"],
    "joern-unchecked-quantity": ["positive_guard"],
    "joern-toctou-check-then-write": ["lock_guard"],
}


def _rel(target: str, path: str) -> Optional[str]:
    """`path` relative to the scanned target, forward slashes; the file's own name when the
    target IS that file (a single-file scan). None when `path` is outside the target."""
    t, f = Path(target).resolve(), Path(path).resolve()
    if t.is_file():
        return f.name if f == t else None
    try:
        return f.relative_to(t).as_posix()
    except ValueError:
        return None


def _split_function(fn: str) -> tuple[str, str]:
    """'OrderViewSet.cancel' -> ('OrderViewSet', 'cancel'); 'get_order' -> ('', 'get_order').
    Joern names a method by its bare name and knows its class separately."""
    parts = [x.strip() for x in (fn or "").split(".") if x.strip()]
    if not parts:
        return "", ""
    return (parts[-2] if len(parts) > 1 else ""), parts[-1]


def _method_of(fn: str) -> str:
    return _split_function(fn)[1]


def _hits(findings, rel: str, method: str, cls: str = "") -> list[dict]:
    """Findings on (rel file, method[, class]). The class is matched when the request named
    one, so a same-named method in another class of the file cannot drive the verdict."""
    out = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        meta = d.get("meta") or {}
        if meta.get("method") != method:
            continue
        if cls and meta.get("class", "") != cls:
            continue
        if Path(d["path"]).as_posix().replace("\\", "/").endswith(rel):
            out.append({"rule_id": d["rule_id"], "line": d["line"], "cwe_id": d.get("cwe_id"),
                        "class": meta.get("class", ""), "slots": meta.get("slots", "")})
    return out


def _key(f, root: str) -> tuple:
    """(path relative to the scan root, method, rule, class) - comparable across the two copies."""
    d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
    rel = _rel(root, d["path"]) or Path(d["path"]).name
    meta = d.get("meta") or {}
    return (rel, meta.get("method", ""), d["rule_id"], meta.get("class", ""))


# --------------------------------------------------------------------------- #
# the decision - pure
# --------------------------------------------------------------------------- #

def decide(rule_id: str, before_hits: Optional[list[dict]], after_hits: list[dict],
           reverify: Optional[dict], regressions: list[dict]) -> dict:
    """Turn the two scan results into the O3 verdict. `before_hits` None = unknown (no
    before state); `reverify` is the Scala's description of the patched method."""
    fam, sink_keys = _RULE_GUARD.get(rule_id, ("", ()))
    fired_before = None if before_hits is None else any(h["rule_id"] == rule_id for h in before_hits)
    refires = any(h["rule_id"] == rule_id for h in after_hits)
    methods = (reverify or {}).get("methods") or []
    m = methods[0] if methods else {}
    guards = (m.get("guards") or {}).get(fam, []) if fam else []
    sinks = m.get("sinks") or {}
    sink_present = any(int(sinks.get(k, 0) or 0) > 0 for k in sink_keys) if sinks else None
    # a candidate ON this method is proof the method exists, whatever the reverify block says
    method_found = bool((reverify or {}).get("found", True)) or bool(after_hits)

    if not method_found:
        reason = "method not found after the fix (renamed or removed) - nothing to verify"
    elif refires:
        reason = "the locator still fires on the patched method: the exploitable path is still there"
    elif fired_before is False:
        reason = "the locator did not fire before the fix either; nothing to converge on"
    elif guards:
        reason = f"guard now present ({', '.join(guards[:3])}); the locator is silent"
    elif sink_present is False:
        reason = "the sink is gone from the method; the locator is silent"
    else:
        reason = "the locator is silent, but no guard token is visible and the sink remains - review by hand"
    if regressions and not refires:
        reason += f"; BUT {len(regressions)} new candidate(s) appeared elsewhere"

    converged = method_found and not refires and (fired_before is not False) and not regressions
    return {"converged": converged, "locator_refires": refires, "fired_before": fired_before,
            "guard_present": bool(guards), "guard_evidence": guards,
            "sink_present": sink_present, "method_found": method_found,
            "regressions": regressions, "reason": reason}


# --------------------------------------------------------------------------- #
# the two modes
# --------------------------------------------------------------------------- #

def _copy_tree(src: str) -> Path:
    dest = runtime.TOOLS / "_rampart_joern_tmp" / f"reverify_{uuid.uuid4().hex[:10]}"
    dest.mkdir(parents=True, exist_ok=True)
    s = Path(src)
    if s.is_file():
        shutil.copy2(s, dest / s.name)
    else:
        shutil.copytree(s, dest / "tree", ignore=apply_svc._ignore_copy)
        dest = dest / "tree"
    return dest


def _code_only(src: str) -> str:
    """Source with string literals and comments blanked IN PLACE (same length, spaces), so a
    docstring saying 'lock' or a comment saying 'authorized' cannot pass as a guard - the same
    literal/code split the CPG rules keep - while every other character keeps its position, so
    multi-token guards (`!= request.user`, `abort(403`, `owner=request.user`) still match.
    If the source does not tokenize, returns "" (never the raw text: a broken fix with a lying
    docstring must not pass either)."""
    skip = {tokenize.STRING, tokenize.COMMENT}
    for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):   # 3.12+ f-string pieces
        if hasattr(tokenize, name):
            skip.add(getattr(tokenize, name))
    lines = src.splitlines(keepends=True)
    try:
        spans = [(t.start, t.end) for t in tokenize.generate_tokens(io.StringIO(src).readline) if t.type in skip]
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return ""
    for (r1, c1), (r2, c2) in spans:                    # rows are 1-based
        for r in range(r1, r2 + 1):
            if r - 1 >= len(lines):
                break
            line = lines[r - 1]
            a = c1 if r == r1 else 0
            b = c2 if r == r2 else len(line.rstrip("\r\n"))
            lines[r - 1] = line[:a] + " " * max(0, b - a) + line[b:]
    return "".join(lines)


def _pattern_fallback(target: str, after_file: Path, function: str, rule_id: str,
                      pack: Optional[str]) -> dict:
    """Joern unavailable: does the patched function's CODE (not its strings or comments) contain
    a guard token for the rule, using the same pack the CPG path would have used? Weaker on
    purpose and labelled as such."""
    cls, method = _split_function(function)
    text = ""
    try:
        src = after_file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
        lines = src.splitlines()
        # (class name, def) pairs so `Class.method` picks the right one of two same-named defs
        def walk(node, owner):
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, ast.ClassDef):
                    yield from walk(ch, ch.name)
                elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield owner, ch
                    yield from walk(ch, owner)
                else:
                    yield from walk(ch, owner)
        for owner, node in walk(tree, ""):
            if node.name == method and (not cls or owner == cls):
                text = "\n".join(lines[node.lineno - 1:(node.end_lineno or node.lineno)])
                break
    except (OSError, SyntaxError, ValueError):
        pass
    chosen, _why = vocab.resolve(target, pack if pack is not None else getattr(config, "JOERN_PACK", "auto"))
    eff, _ = vocab.load(chosen, allow_unlisted=bool(getattr(config, "JOERN_PACK_ALLOW_UNLISTED", False)))
    if eff is None:
        eff, _ = vocab.load(vocab.BASE_ID, allow_unlisted=True)
    toks = []
    for slot in _RULE_SLOTS.get(rule_id, []):
        toks += eff["slots"].get(slot, {}).get("values", []) if eff else []
    low = _code_only(text).lower().replace(" = ", "=")
    found = sorted({t for t in toks if t in low})
    return {"guard_present": bool(found), "guard_evidence": [f"text:{t}" for t in found],
            "method_found": bool(text), "pack": chosen}


def verify(target: str, path: str, function: str, rule_id: str, *,
           fixed_code: Optional[str] = None, start_line: Optional[int] = None,
           end_line: Optional[int] = None, original_code: Optional[str] = None,
           before_dir: Optional[str] = None, pack: Optional[str] = None,
           regress: bool = True) -> dict:
    """Never raises. See the module docstring for the two modes."""
    t0 = time.time()
    rel = _rel(target, path)
    cls, method = _split_function(function)
    if rel is None:
        return {"ok": False, "error": f"{path} is not inside the scanned target {target}"}
    if not method:
        return {"ok": False, "error": "function name is required"}
    # These three strings are substituted into Scala source. _render() escapes them, but a
    # value that is not a plain relative .py path / identifier is wrong anyway: refuse early.
    why = joern_scan.valid_reverify_target(rel, method)
    if why is None and cls and not joern_scan._METHOD_RE.match(cls):
        why = f"class name must be a Python identifier: {cls!r}"
    if why:
        return {"ok": False, "code": "bad_request", "error": why}
    if not rule_id.startswith("joern-"):
        return {"ok": False, "code": "not_cpg", "error": "re-verification runs the CPG locator; rule_id must be a joern-* rule"}
    scratch: Optional[Path] = None
    try:
        if fixed_code is not None:
            if start_line is None or end_line is None:
                return {"ok": False, "error": "start_line and end_line are required with fixed_code"}
            scratch = _copy_tree(target)
            after_dir = str(scratch)
            after_file = scratch / rel                   # rel is the file's name for a lone file
            applied = apply_svc.apply_fix(str(after_file), start_line, end_line, fixed_code, original_code)
            if not applied.get("ok"):
                return {"ok": False, **{k: v for k, v in applied.items() if k != "ok"}, "mode": "preview"}
            before = target
            mode = "preview"
        else:
            mode = "post_apply"
            before = before_dir
            if Path(target).is_file():
                # pysrc2cpg reports an empty filename for a lone file, which no (rel, method)
                # lookup can match: build the CPG on a directory holding a copy of it instead
                scratch = _copy_tree(target)
                after_dir = str(scratch)
                after_file = scratch / Path(target).name
            else:
                after_dir = target
                after_file = Path(path)

        if not after_file.is_file():
            return {"ok": False, "code": "not_found", "error": f"{rel} does not exist in the target", "mode": mode}
        ok, why = joern_scan.enabled(after_dir)
        if not ok:
            pf = _pattern_fallback(after_dir, after_file, function, rule_id, pack)
            return {"ok": True, "mode": mode, "reverify_method": "pattern", "converged": pf["guard_present"],
                    "locator_refires": None, "fired_before": None, "regressions": [],
                    **pf, "reason": ("guard token found in the patched function text (pattern fallback; Joern unavailable: " + why + ")")
                    if pf["guard_present"] else "no guard token in the patched function text (pattern fallback; Joern unavailable: " + why + ")",
                    "elapsed_ms": int((time.time() - t0) * 1000)}

        after_f, after_diag = joern_scan.scan(after_dir, pack=pack, reverify=(rel, method, cls))
        if not after_diag.get("used"):
            return {"ok": False, "mode": mode, "reverify_method": "cpg",
                    "error": "CPG phase did not run on the patched copy: " + str(after_diag.get("reason")),
                    "elapsed_ms": int((time.time() - t0) * 1000)}
        after_hits = _hits(after_f, rel, method, cls)

        before_hits: Optional[list[dict]] = None
        regressions: list[dict] = []
        before_diag: dict = {}
        if before and regress:
            before_f, before_diag = joern_scan.scan(before, pack=pack, reverify=(rel, method, cls))
            if before_diag.get("used"):
                before_hits = _hits(before_f, rel, method, cls)
                seen = {_key(f, before) for f in before_f}
                for f in after_f:
                    k = _key(f, after_dir)
                    if k not in seen and not (k[0] == rel and k[1] == method and (not cls or k[3] == cls)):
                        d = f.to_dict()
                        regressions.append({"path": k[0], "line": d["line"], "method": k[1], "rule_id": k[2]})

        verdict = decide(rule_id, before_hits, after_hits, after_diag.get("reverify"), regressions)
        return {"ok": True, "mode": mode, "reverify_method": "cpg", **verdict,
                "evidence": {"before": before_hits, "after": after_hits,
                             "method": (after_diag.get("reverify") or {}).get("methods"),
                             "pack": (after_diag.get("pack") or {}).get("tag"),
                             "cpg_mode": after_diag.get("mode"),
                             "cpg_ms": {"after": after_diag.get("elapsed_ms"), "before": before_diag.get("elapsed_ms")}},
                "elapsed_ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "elapsed_ms": int((time.time() - t0) * 1000)}
    finally:
        if scratch is not None:
            root = scratch if scratch.name != "tree" else scratch.parent
            shutil.rmtree(root, ignore_errors=True)
