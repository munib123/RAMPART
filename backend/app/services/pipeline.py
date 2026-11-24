"""Orchestration: scan -> extract slice -> RAG ground -> Gemini verify -> ranked report."""
from __future__ import annotations

import os
import time

from app import config
from app.services import rag, gemini, scan_cache
from app.services.scanner import Finding, get_scanner
from app.services.joern import scan as joern_scan
from app.services.extract import SliceCache, extract_slice


def _dedupe(findings: list) -> list:
    """Drop duplicate findings at the same (file, line, cwe). Keep the first."""
    seen, out = set(), []
    for f in findings:
        key = (f.get("path"), f.get("line"), f.get("cwe_id"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

_SEV_W = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
_VERDICT_W = {"Confirmed": 4, "Likely": 3, "Informational": 2, "Unverified": 1,
              "Error": 1, "False positive": 0}


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000.0, 1)


def run_scan(path: str, scanner_name: str = None, scope: dict = None, fresh: bool = False) -> dict:
    """Run one scan. The slice cache lives for exactly this scan and is cleared in `finally`,
    so an edited file can never be served from a previous run. `fresh` bypasses the raw
    scanner/Joern cache (the result is still written back)."""
    cache = SliceCache()
    try:
        return _run_scan(path, scanner_name, scope, cache, fresh)
    finally:
        cache.clear()


def _run_scan(path: str, scanner_name: str, scope: dict, cache: SliceCache,
              fresh: bool = False) -> dict:
    scanner_name = scanner_name or config.DEFAULT_SCANNER
    path = os.path.abspath(path or config.DEFAULT_TARGET)
    t_start = time.perf_counter()
    t0 = time.time()
    timings = {"scan": 0.0, "joern": 0.0, "extract": 0.0, "rag": 0.0, "rank": 0.0, "total": 0.0}
    if not os.path.exists(path):
        return {"ok": False, "error": f"path does not exist: {path}"}

    scanner = get_scanner(scanner_name)
    scanner_name = scanner.name          # resolve "auto" to what actually runs
    ok, why = scanner.available()
    if not ok:
        return {"ok": False, "error": f"scanner '{scanner_name}' unavailable: {why}"}

    # Joern / CPG phase: ADD the SAST-blind logic-bug candidates (IDOR, mass assignment,
    # unchecked quantity, TOCTOU) that the pattern scanner structurally cannot see. Joern only
    # LOCATES; the candidates are verified by the same LLM step as everything else. It never
    # raises - a failure can only mean "no extra findings", and the reason is carried in `joern`
    # so a dead CPG phase is visible in the response and the UI, never silent.
    run_joern, joern_why = joern_scan.enabled(path)

    # Reuse the raw subprocess output when the tree and toolchain are byte-identical. The
    # key is computed before the scanner runs; the final report is never cached (extract,
    # RAG and verification below still run, so verdicts stay current).
    key, cached = "", None
    if scan_cache.enabled():
        fingerprint = scan_cache.tree_fingerprint(path)
        key = scan_cache.cache_key(
            fingerprint, path, scanner_name,
            str(getattr(scanner, "config", "") or ""),
            f"{config.JOERN_ENABLED}:{run_joern}:{config.JOERN_PACK}",
            joern_scan.rules_sha256(),
        )
        if not fresh:
            cached = scan_cache.load(key)

    if cached is not None:
        findings_raw = [Finding(**d) for d in cached.get("findings", [])]
        joern = dict(cached.get("joern") or {})
        joern.update(cache_hit=True, elapsed_ms=0)
        print(f"[scan-cache] hit {key[:12]} - reusing {len(findings_raw)} raw finding(s)")
    else:
        t = time.perf_counter()
        findings_raw = scanner.scan(path)
        timings["scan"] = _ms(t)

        joern = {"used": False, "reason": joern_why, "elapsed_ms": 0, "candidates": 0}
        if run_joern:
            t = time.perf_counter()
            joern_raw, joern = joern_scan.scan(path)
            timings["joern"] = _ms(t)
            if joern_raw:
                findings_raw = list(findings_raw) + joern_raw

        if key:
            scan_cache.store(key, [f.to_dict() for f in findings_raw], joern)
            print(f"[scan-cache] stored {key[:12]} - {len(findings_raw)} raw finding(s)")

    # Phase 1 - extract slices (cheap file reads) for every finding. The per-scan cache means a
    # file with N findings is read and AST-parsed once, not N times.
    t = time.perf_counter()
    prepared = []
    for f in findings_raw:
        d = f.to_dict()
        slice_ = extract_slice(d["path"], d["line"], cache)
        prepared.append({**d, "slice": slice_, "exemplars": []})
    prepared = _dedupe(prepared)
    timings["extract"] = _ms(t)

    # Verify the most severe N with the LLM in ONE batched call (bounds cost + respects daily quota).
    sev = lambda x: _SEV_W.get(x["severity"], 0)
    cpg = sorted([x for x in prepared if x["tool"] == "joern"], key=sev, reverse=True)
    rest = sorted([x for x in prepared if x["tool"] != "joern"], key=sev, reverse=True)
    q = min(config.JOERN_LLM_QUOTA, len(cpg))          # CPG candidates get reserved slots
    to_verify = cpg[:q] + rest[:config.MAX_LLM_FINDINGS - q]
    skipped = cpg[q:] + rest[config.MAX_LLM_FINDINGS - q:]

    # Phase 2 - RAG grounding, only for the findings that get verified. One batched call dedupes
    # repeated (message, CWE) queries and embeds every unique one in a single encode().
    t = time.perf_counter()
    queries = [(f"{x['message']} {x['slice']['code']}".strip(), x["cwe_id"]) for x in to_verify]
    for x, exemplars in zip(to_verify, rag.retrieve_many(queries)):
        x["exemplars"] = exemplars
    timings["rag"] = _ms(t)

    verdicts = gemini.analyze_batch(to_verify, scope)
    for x, v in zip(to_verify, verdicts):
        x["verdict"] = v

    for x in skipped:
        x["verdict"] = {"available": False, "verdict": "Unverified", "confidence": 0,
                        "cwe": x["cwe_id"], "vuln_class": x["title"],
                        "explanation": "Not verified: beyond the per-scan LLM limit.", "fix_suggestion": ""}

    t = time.perf_counter()
    findings = to_verify + skipped

    def rank(x):
        v = x["verdict"]
        return (_VERDICT_W.get(v.get("verdict", ""), 0),
                _SEV_W.get(x["severity"], 0),
                v.get("confidence", 0))
    findings.sort(key=rank, reverse=True)
    timings["rank"] = _ms(t)

    counts = {"total": len(findings)}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    timings["total"] = _ms(t_start)
    if config.PROFILE:
        for name, ms in timings.items():
            print(f"[profile] {name:7s} {ms:9.1f} ms")

    return {
        "ok": True,
        "target": path,
        "scanner": scanner_name,
        "joern": joern,
        "scope": scope or {},
        "llm": {"enabled": gemini.available(), "model": config.GEMINI_MODEL if gemini.available() else None},
        "counts": counts,
        "elapsed_s": round(time.time() - t0, 1),
        "timings": timings,
        "findings": findings,
    }
