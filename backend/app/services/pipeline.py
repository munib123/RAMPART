"""Orchestration: scan -> extract slice -> RAG ground -> Gemini verify -> ranked report."""
from __future__ import annotations

import os
import time

from app import config
from app.services import rag, gemini
from app.services.scanner import get_scanner
from app.services.extract import extract_slice


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


def run_scan(path: str, scanner_name: str = None, scope: dict = None) -> dict:
    scanner_name = scanner_name or config.DEFAULT_SCANNER
    path = os.path.abspath(path or config.DEFAULT_TARGET)
    t0 = time.time()
    if not os.path.exists(path):
        return {"ok": False, "error": f"path does not exist: {path}"}

    scanner = get_scanner(scanner_name)
    scanner_name = scanner.name          # resolve "auto" to what actually runs
    ok, why = scanner.available()
    if not ok:
        return {"ok": False, "error": f"scanner '{scanner_name}' unavailable: {why}"}

    findings_raw = scanner.scan(path)

    # Phase 1 - extract slices (cheap file reads) for every finding.
    prepared = []
    for f in findings_raw:
        d = f.to_dict()
        slice_ = extract_slice(d["path"], d["line"])
        prepared.append({**d, "slice": slice_, "exemplars": []})
    prepared = _dedupe(prepared)

    # Verify the most severe N with the LLM in ONE batched call (bounds cost + respects daily quota).
    prepared.sort(key=lambda x: _SEV_W.get(x["severity"], 0), reverse=True)
    to_verify = prepared[:config.MAX_LLM_FINDINGS]
    skipped = prepared[config.MAX_LLM_FINDINGS:]

    # Phase 2 - RAG grounding, only for the findings that get verified. Embedding + Chroma
    # queries are the slow part (sequential; embedder/Chroma are not thread-safe), and on a
    # large codebase grounding hundreds of unverified findings stalled the whole scan.
    for x in to_verify:
        query = f"{x['message']} {x['slice']['code']}".strip()
        x["exemplars"] = rag.retrieve(query, cwe_id=x["cwe_id"])

    verdicts = gemini.analyze_batch(to_verify, scope)
    for x, v in zip(to_verify, verdicts):
        x["verdict"] = v

    for x in skipped:
        x["verdict"] = {"available": False, "verdict": "Unverified", "confidence": 0,
                        "cwe": x["cwe_id"], "vuln_class": x["title"],
                        "explanation": "Not verified: beyond the per-scan LLM limit.", "fix_suggestion": ""}
    findings = to_verify + skipped

    def rank(x):
        v = x["verdict"]
        return (_VERDICT_W.get(v.get("verdict", ""), 0),
                _SEV_W.get(x["severity"], 0),
                v.get("confidence", 0))
    findings.sort(key=rank, reverse=True)

    counts = {"total": len(findings)}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "ok": True,
        "target": path,
        "scanner": scanner_name,
        "scope": scope or {},
        "llm": {"enabled": gemini.available(), "model": config.GEMINI_MODEL if gemini.available() else None},
        "counts": counts,
        "elapsed_s": round(time.time() - t0, 1),
        "findings": findings,
    }
