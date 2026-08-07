"""
Gemini verification. Given a scanner finding + the code slice + retrieved real-world exemplars,
Gemini returns a grounded verdict. Key is read from the environment only (never hardcoded).

If no key is configured the module degrades gracefully so the app still runs (findings + RAG show;
the verdict says the LLM step is unavailable).
"""
from __future__ import annotations

import json
import re
import threading

from app import config

_client = None
_lock = threading.Lock()


def available() -> bool:
    return bool(config.GEMINI_API_KEY)


def ensure_configured():
    """Create the client exactly once, safely across threads (called before the LLM pool)."""
    global _client
    with _lock:
        if _client is None:
            from google import genai
            _client = genai.Client(
                api_key=config.GEMINI_API_KEY,
                http_options={"timeout": 120_000},   # ms; a stalled connection must not hang the scan
            )


# a backslash not starting a valid JSON escape (\" \\ \/ \b \f \n \r \t \uXXXX)
_BAD_ESCAPE = re.compile(r'\\(?!["\\/bfnrtu])')

_PROSE_FIELDS = ("explanation", "fix_suggestion", "vuln_class", "summary")


_EM_DASH = chr(0x2014)  # em dash


def _strip_em_dashes(d: dict) -> dict:
    """House style: no em dashes (U+2014) in UI prose. Prose fields only, never code."""
    for k in _PROSE_FIELDS:
        v = d.get(k)
        if isinstance(v, str) and _EM_DASH in v:
            d[k] = v.replace(f" {_EM_DASH} ", ", ").replace(_EM_DASH, ", ")
    return d


def _loads_lenient(text: str):
    """Parse LLM JSON output, repairing the faults models still produce even with
    response_mime_type=application/json: markdown fences around the object, and raw
    backslashes inside strings (Windows paths, regex like \\d) that json.loads rejects
    as invalid escapes."""
    s = (text or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"```\s*$", "", s)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_BAD_ESCAPE.sub(r"\\\\", s))
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", s, re.DOTALL)   # last resort: outermost JSON object
        if not m:
            raise
        return json.loads(_BAD_ESCAPE.sub(r"\\\\", m.group(0)))


def _prompt(finding: dict, code: str, exemplars: list[dict]) -> str:
    ex = "\n\n".join(
        f"- [{e.get('source')} · {e.get('cwe_id')} · sev {e.get('severity')}] {e.get('title')}\n  {e.get('text','')[:300]}"
        for e in exemplars
    ) or "(no matching exemplars retrieved)"
    return f"""You are RAMPART's verification step. A static analyser flagged code as vulnerable.
Decide whether it is a TRUE positive, grounded in the real disclosed vulnerabilities retrieved below.

FINDING
- tool: {finding.get('tool')}   rule: {finding.get('rule_id')}
- CWE: {finding.get('cwe_id')}
- location: {finding.get('path')}:{finding.get('line')}
- message: {finding.get('message')}

CODE SLICE
```
{code[:2500]}
```

RETRIEVED REAL-WORLD EXEMPLARS (same class of bug, from a disclosed-vulnerability knowledge base)
{ex}

Return ONLY a JSON object with these fields:
- "verdict": one of "Confirmed" | "Likely" | "Informational" | "False positive"
- "confidence": number 0-100
- "cwe": the most accurate CWE id (e.g. "CWE-78")
- "vuln_class": short human name of the weakness
- "explanation": 2-4 plain sentences, calm and specific, on why this is or isn't exploitable here
- "fix_suggestion": one concrete remediation sentence (no code)
Be honest: if the code is actually safe or the finding is low-signal, say "False positive" or "Informational".
Never use em dashes in any text; use commas, colons or periods instead."""


def _scope_line(scope: dict) -> str:
    if not scope:
        return ""
    parts = []
    if scope.get("platform"):
        parts.append(f"platform={scope['platform']}")
    if scope.get("stack"):
        parts.append("stack=" + ",".join(scope["stack"]) if isinstance(scope["stack"], list) else f"stack={scope['stack']}")
    if scope.get("priorities"):
        parts.append("priorities=" + ",".join(scope["priorities"]) if isinstance(scope["priorities"], list) else f"priorities={scope['priorities']}")
    if not parts:
        return ""
    return ("\nPROJECT CONTEXT: " + " · ".join(parts) +
            ". Weigh findings that matter for this context more heavily, and say so in the explanation when relevant.\n")


def _batch_prompt(items: list[dict], scope: dict = None) -> str:
    blocks = []
    for i, it in enumerate(items):
        ex = "; ".join(f"[{e.get('source')} {e.get('cwe_id')}] {e.get('title')}" for e in it.get("exemplars", [])[:3]) or "(none)"
        blocks.append(
            f"### Finding {i}\n"
            f"- rule: {it.get('rule_id')} | CWE: {it.get('cwe_id')} | location: {it.get('path')}:{it.get('line')}\n"
            f"- message: {it.get('message')}\n"
            f"- retrieved exemplars (same bug class, from real disclosed vulns): {ex}\n"
            f"CODE:\n```\n{(it.get('slice',{}).get('code','') or '')[:1500]}\n```"
        )
    return (
        "You are RAMPART's verification step. A static analyser flagged the code locations below. "
        "For EACH finding decide whether it is a true positive, grounded in the retrieved real-world exemplars. "
        "Be honest: mark safe code as \"False positive\" and low-signal notes as \"Informational\"."
        + _scope_line(scope) + "\n"
        + "\n\n".join(blocks) +
        "\n\nReturn ONLY JSON: {\"results\":[{\"index\":<int>,\"verdict\":\"Confirmed|Likely|Informational|False positive\","
        "\"confidence\":<0-100>,\"cwe\":\"CWE-..\",\"vuln_class\":\"short name\",\"explanation\":\"2-4 calm, specific sentences\","
        "\"fix_suggestion\":\"one concrete remediation sentence\"}]} with exactly one result per finding index. "
        "Never use em dashes in any text; use commas, colons or periods instead."
    )


def _err_verdict(it: dict, msg: str) -> dict:
    return {"available": False, "verdict": "Error", "confidence": 0, "cwe": it.get("cwe_id", ""),
            "vuln_class": it.get("title", ""), "explanation": f"LLM verification failed: {msg}", "fix_suggestion": ""}


def analyze_batch(items: list[dict], scope: dict = None) -> list[dict]:
    """Verify all findings in as few calls as possible (chunks of LLM_BATCH). One call ≈ one request."""
    import time
    n = len(items)
    if not available():
        return [{"available": False, "verdict": "Unverified", "confidence": 0, "cwe": it.get("cwe_id", ""),
                 "vuln_class": it.get("title", ""),
                 "explanation": "LLM verification is unavailable. Set GEMINI_API_KEY in .env.",
                 "fix_suggestion": ""} for it in items]
    ensure_configured()
    out: list[dict] = [None] * n
    for start in range(0, n, config.LLM_BATCH):
        group = items[start:start + config.LLM_BATCH]
        parsed, last = None, ""
        for attempt in range(4):
            try:
                resp = _client.models.generate_content(
                    model=config.GEMINI_MODEL,
                    contents=_batch_prompt(group, scope),
                    config={"response_mime_type": "application/json", "temperature": 0},
                )
                data = _loads_lenient(resp.text)
                # tolerate the shapes models actually emit: {"results":[...]}, a bare [...]
                # array, or a single {...} object; and results that omit "index" (map positionally).
                if isinstance(data, dict):
                    results = data.get("results") or data.get("findings") or [data]
                elif isinstance(data, list):
                    results = data
                else:
                    results = []
                parsed = {}
                for pos, r in enumerate(results):
                    if not isinstance(r, dict):
                        continue
                    try:
                        idx = int(r["index"]) if "index" in r else pos
                    except (ValueError, TypeError):
                        idx = pos
                    parsed[idx] = r
                break
            except Exception as e:
                last = f"{type(e).__name__}: {str(e)[:150]}"
                if ("429" in str(e) or "quota" in str(e).lower()) and attempt < 3:
                    time.sleep([5, 12, 24][attempt]); continue
                if isinstance(e, (json.JSONDecodeError, KeyError, ValueError, AttributeError, TypeError)) and attempt < 1:
                    continue   # malformed output - one fresh generation usually parses
                break
        for i, it in enumerate(group):
            r = parsed.get(i) if parsed else None
            if r:
                r["available"] = True
                out[start + i] = _strip_em_dashes(r)
            else:
                out[start + i] = _err_verdict(it, last or "no result for this finding")
    return out


def _fix_prompt(finding: dict, code: str, exemplars: list[dict]) -> str:
    ex = "; ".join(f"[{e.get('source')} {e.get('cwe_id')}] {e.get('title')}" for e in (exemplars or [])[:3]) or "(none)"
    return (
        "You are RAMPART's remediation step. Rewrite the vulnerable code below so the weakness is "
        "fixed, preserving behavior, function names and signatures. Change as little as possible; "
        "do not add unrelated edits.\n\n"
        f"WEAKNESS: {finding.get('cwe_id')} - {finding.get('title')}\n"
        f"FINDING: {finding.get('message')}\n"
        f"SIMILAR REAL FIXES (context): {ex}\n\n"
        f"VULNERABLE CODE:\n```\n{(code or '')[:3000]}\n```\n\n"
        "Return ONLY JSON: {\"fixed_code\": \"<the full corrected version of the same code block, "
        "no markdown fences>\", \"summary\": \"<one calm sentence on what changed and why it is safe, "
        "never using em dashes>\"}"
    )


def generate_fix(finding: dict, code: str, exemplars: list[dict] = None) -> dict:
    """On-demand: produce a corrected version of one vulnerable code slice (one Gemini call)."""
    if not available():
        return {"available": False, "error": "LLM unavailable. Set GEMINI_API_KEY in .env."}
    import time
    ensure_configured()
    prompt = _fix_prompt(finding, code, exemplars or [])
    last = ""
    for attempt in range(4):
        try:
            resp = _client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=prompt,
                config={"response_mime_type": "application/json", "temperature": 0})
            data = _loads_lenient(resp.text)
            return _strip_em_dashes({"available": True, "fixed_code": (data.get("fixed_code") or "").strip(),
                                     "summary": (data.get("summary") or "").strip()})
        except Exception as e:
            last = f"{type(e).__name__}: {str(e)[:180]}"
            if ("429" in str(e) or "quota" in str(e).lower()) and attempt < 3:
                time.sleep([5, 12, 24][attempt]); continue
            if isinstance(e, (json.JSONDecodeError, ValueError)) and attempt < 1:
                continue   # malformed output - one fresh generation usually parses
            return {"available": False, "error": last}
    return {"available": False, "error": last}


def analyze(finding: dict, code: str, exemplars: list[dict]) -> dict:
    if not available():
        return {"available": False, "verdict": "Unverified", "confidence": 0,
                "cwe": finding.get("cwe_id", ""), "vuln_class": finding.get("title", ""),
                "explanation": "LLM verification is unavailable. Set GEMINI_API_KEY in .env to enable grounded verdicts.",
                "fix_suggestion": ""}
    import time
    ensure_configured()
    prompt = _prompt(finding, code, exemplars)
    backoffs = [5, 12, 24]  # free-tier rate limits (429) recover within a minute
    last = ""
    for attempt in range(len(backoffs) + 1):
        try:
            resp = _client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=prompt,
                config={"response_mime_type": "application/json", "temperature": 0},
            )
            data = _loads_lenient(resp.text)
            data["available"] = True
            return _strip_em_dashes(data)
        except Exception as e:
            last = f"{type(e).__name__}: {str(e)[:180]}"
            is_rate = "429" in str(e) or "ResourceExhausted" in type(e).__name__ or "quota" in str(e).lower()
            if is_rate and attempt < len(backoffs):
                time.sleep(backoffs[attempt])
                continue
            break
    return {"available": False, "verdict": "Error", "confidence": 0,
            "cwe": finding.get("cwe_id", ""), "vuln_class": finding.get("title", ""),
            "explanation": f"LLM verification failed: {last}",
            "fix_suggestion": ""}
