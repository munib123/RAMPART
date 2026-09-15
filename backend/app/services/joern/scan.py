"""
Joern / CPG phase - the SAST-blind logic-bug locator.

semgrep and bandit are pattern matchers: they see a dangerous call, not a missing check. The
high-value bugs in a web app are the opposite - an ABSENCE (no ownership check, no allow-list,
no > 0 guard, no lock) that only makes sense across a whole function. Those are invisible to a
pattern scanner but visible in a Code Property Graph.

This module runs Joern's Python frontend (pysrc2cpg) over the target, executes the locator
rules in rules/locators.sc, and returns candidates in the same normalized `Finding` shape the
other scanners emit. Joern only LOCATES; the candidates flow through the identical
extract -> RAG-ground -> Gemini-verify pipeline, where the LLM confirms or rejects each one.

Contract with the pipeline: this phase is ADDITIVE and NEVER RAISES. On any failure it returns
no findings plus a diag dict that says why, so a dead CPG phase is visible rather than silent.

Two execution modes (P3):
  server   the sidecar in server.py is up: the rules file is split on its `// @@` markers and
           each section is one /query-sync request. The JVM start is paid once per backend
           process; a compile error in one rule costs that rule only.
  script   one `joern --script` per scan. The fallback whenever the server is not ready.
Both produce the same findings.tsv + diag.json and go through the same _collect().

Vocabulary packs (P5): the rules file holds the four rule SHAPES; the token lists (what an
ownership check, a lock, an allow-list or an object id looks like) come from a JSON pack under
vocab/packs/, chosen per target (JOERN_PACK=auto detects flask / django from the target). The
pack is validated against vocab/schema.json here, in Python, before anything reaches the JVM;
an invalid or unlisted pack falls back to _base and the diag says so. The Scala is frozen and
hashed, the pack is hashed separately, and both hashes travel with every finding.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from app import config
from app.services.scanner import Finding
from app.services.joern import runtime, server
from app.services.joern.vocab import validate as vocab

HERE = Path(__file__).resolve().parent
RULES = HERE / "rules" / "locators.sc"

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}

# human-readable vuln class per locator rule (used as the finding title)
_TITLES = {
    "joern-idor-missing-ownership": "Insecure direct object reference (IDOR)",
    "joern-mass-assignment": "Mass assignment",
    "joern-unchecked-quantity": "Unchecked quantity (business logic)",
    "joern-toctou-check-then-write": "Race condition (TOCTOU)",
}

# markers for the lines that actually explain a failure, inside Joern's very long JVM output
_ERR_MARKERS = ("Exception", "Error", "error:", "Caused by:", "Failed", "failed")

# `// @@ <kind> [<name>]` section markers in the rules file
_SECTION = re.compile(r"^// @@ (\S+)(?: (\S+))?[ \t]*$", re.M)


def _error_summary(stdout: str, stderr: str, limit: int = 8) -> list[str]:
    """Pull the lines that explain a Joern failure out of its output. A script exception buries
    the real cause under ~40 frames of replpp/mainargs stack; prefer marker lines (plus the line
    after, which carries detail like an offending regex) and fall back to the tail."""
    lines = [ln.rstrip() for ln in f"{stdout}\n{stderr}".splitlines() if ln.strip()]
    lines = [ln for ln in lines if not ln.lstrip().startswith("[INFO ]")] or lines
    keep, i = [], 0
    while i < len(lines):
        ln = lines[i].strip()
        if not ln.startswith("at ") and any(m in ln for m in _ERR_MARKERS):
            keep.append(ln)
            nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if nxt and not nxt.startswith("at ") and not any(m in nxt for m in _ERR_MARKERS):
                keep.append(nxt)
                i += 1
        i += 1
    return [ln[:300] for ln in (keep or lines[-limit:])[-limit:]]


def _has_python_files(path: str) -> bool:
    p = Path(path)
    if p.is_file():
        return p.suffix == ".py"
    for root, dirs, files in os.walk(p):
        dirs[:] = [d for d in dirs if d not in {".venv", "venv", ".git", "node_modules",
                                              "__pycache__", "dist", "build"}]
        if any(f.endswith(".py") for f in files):
            return True
    return False


def available() -> tuple[bool, str]:
    """Is Joern runnable? Delegates to the runtime probe (cached per process)."""
    ok, why, _ = runtime.probe()
    return ok, why


def enabled(path: str) -> tuple[bool, str]:
    """Should the CPG phase run for this scan? Returns (run, reason-if-not).
    auto = run when the runtime is present and the target has Python files."""
    mode = (config.JOERN_ENABLED or "auto").lower()
    if mode in ("off", "false", "0", "no"):
        return False, "JOERN_ENABLED=off"
    ok, why = available()
    if not ok:
        return False, why
    if mode in ("on", "true", "1", "yes"):
        return True, ""
    if not _has_python_files(path):
        return False, "target has no Python files (pysrc2cpg only)"
    return True, ""


def _scratch_root() -> Path:
    return runtime.TOOLS / "_rampart_joern_tmp"


def _workspace_dir() -> Path:
    # Joern creates its workspace relative to the process CWD; script mode sets cwd to the
    # scratch dir, so the project lands under <scratch>/workspace/<proj> and is removed with it.
    return _scratch_root() / "workspace"


def _parse_tsv(text: str, input_dir: str) -> list[Finding]:
    out: list[Finding] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 8:
            continue
        cwe, sev, rel_file, line, method, rule, message, evidence = parts[:8]
        # columns 9-10 (P5): pack tag and slot trace - provenance, optional
        meta = {"method": method} if method else {}
        if len(parts) > 8 and parts[8]:
            meta["pack"] = parts[8]
        if len(parts) > 9 and parts[9]:
            meta["slots"] = parts[9]
        if len(parts) > 10 and parts[10]:                   # column 11 (P7): route reachability
            meta["route"] = parts[10]
        try:
            ln = int(line)
        except ValueError:
            ln = 0
        abs_path = os.path.normpath(os.path.join(input_dir, rel_file.replace("/", os.sep)))
        msg = message if not evidence else f"{message}  [code: {evidence}]"
        out.append(Finding(
            tool="joern",
            rule_id=rule,
            title=_TITLES.get(rule, method),
            path=abs_path,
            line=ln,
            end_line=ln,
            severity=_SEV.get(sev.lower(), "medium"),
            confidence="medium",
            cwe_id=cwe,
            message=msg,
            meta=meta,
        ))
    return out


# --------------------------------------------------------------------------- #
# the two execution modes
# --------------------------------------------------------------------------- #

def _sections(rendered: str) -> list[tuple[str, str, str]]:
    """Split the rendered rules file on `// @@ <kind> [<name>]` -> [(kind, name, code)]."""
    marks = list(_SECTION.finditer(rendered))
    out = []
    for i, m in enumerate(marks):
        body_end = marks[i + 1].start() if i + 1 < len(marks) else len(rendered)
        out.append((m.group(1), m.group(2) or "", rendered[m.end():body_end]))
    return out


def _render(input_dir: str, out_file: Path, diag_file: Path, proj: str,
            pack_file: Path | None = None, pack_tag: str = "",
            reverify: tuple[str, str] | None = None, reverify_out: Path | None = None) -> str:
    fwd = lambda p: str(p).replace("\\", "/")
    base = vocab.pack_path(vocab.BASE_ID)
    rv_file, rv_method = reverify if reverify else ("", "")
    return (RULES.read_text(encoding="utf-8")
            .replace("__INPUT_DIR__", fwd(input_dir))
            .replace("__OUT_FILE__", fwd(out_file))
            .replace("__DIAG_FILE__", fwd(diag_file))
            .replace("__PROJECT__", proj)
            .replace("__PACK_FILE__", fwd(pack_file if pack_file is not None else base))
            .replace("__BASE_PACK_FILE__", fwd(base))
            .replace("__PACK_TAG__", pack_tag)
            .replace("__REVERIFY_FILE__", fwd(rv_file))
            .replace("__REVERIFY_METHOD__", rv_method)
            .replace("__REVERIFY_OUT__", fwd(reverify_out) if reverify_out is not None else ""))


def prepare_pack(target: str, requested: str | None = None, tmp: Path | None = None) -> tuple[Path | None, dict]:
    """Choose, validate and materialise the vocabulary pack for one scan.
    Returns (path to the composed pack json written under tmp, info for the diag). Never raises:
    an invalid/unlisted/missing pack falls back to _base and the reason is in info['fallback'].
    The Scala reads the COMPOSED form (parent values already merged), so what is hashed is what
    runs."""
    req = requested if requested is not None else getattr(config, "JOERN_PACK", "auto")
    chosen, why = vocab.resolve(target, req)
    allow = bool(getattr(config, "JOERN_PACK_ALLOW_UNLISTED", False))
    eff, li = vocab.load(chosen, allow_unlisted=allow)
    info = {"requested": req, "resolved": chosen, "reason": why, "listed": li.get("listed", False)}
    if eff is None:
        info["fallback"] = "; ".join(li.get("errors") or ["unknown error"])[:300]
        eff, li = vocab.load(vocab.BASE_ID, allow_unlisted=True)
        if eff is None:                                  # _base itself broken: installation error
            info.update(id=None, sha256=None, error="; ".join(li.get("errors") or []))
            return None, info
    info.update(id=eff["pack_id"], sha256=li["sha256"], chain=eff.get("chain"),
                authored_from=eff.get("authored_from"), unlisted=not li.get("listed", False),
                values=sum(len(b["values"]) for b in eff["slots"].values()))
    info["tag"] = f"{eff['pack_id']}@{li['sha256'][:12]}"
    if tmp is None:
        return None, info
    pf = tmp / "pack.json"
    pf.write_bytes(vocab.canonical(eff))
    return pf, info


def _collect(out_file: Path, diag_file: Path, input_dir: str, diag: dict,
             compile_errors: dict, reverify_out: Path | None = None) -> list[Finding]:
    """Read findings.tsv + diag.json (+ reverify.json, P8) written by the rules (either mode)."""
    out = _parse_tsv(out_file.read_text(encoding="utf-8", errors="replace"), input_dir)
    if reverify_out is not None and reverify_out.exists():
        try:
            diag["reverify"] = json.loads(reverify_out.read_text(encoding="utf-8"))
        except Exception as e:
            diag["reverify_error"] = f"{type(e).__name__}: {e}"
    rule_state: dict = {}
    if diag_file.exists():
        try:
            d = json.loads(diag_file.read_text(encoding="utf-8"))
            rule_state = d.get("rule_state", {})
            diag.update(methods_seen=d.get("methods_seen"), methods_threw=d.get("methods_threw"))
            if "pack_loaded" in d:                       # what the JVM actually read (P5)
                diag.setdefault("pack", {}).update(loaded=d.get("pack_loaded"), source=d.get("pack_source"))
        except Exception as e:                        # a bad diag must not hide good findings
            diag["diag_error"] = f"{type(e).__name__}: {e}"
    # server mode: a rule whose section failed to COMPILE never ran; say so precisely
    for rule, err in compile_errors.items():
        rule_state[rule] = {"state": "compile_error", "errors": 1, "first_error": err[:300]}
    diag["rule_state"] = rule_state
    for r, s in rule_state.items():
        if s.get("state") in ("threw", "compile_error"):
            print(f"[joern]     RULE {s['state'].upper()} {r}: {s.get('first_error')}")
    return out


def _run_script(info, script: Path, tmp: Path, out_file: Path, diag: dict) -> Optional[str]:
    """Script mode: one `joern --script` per scan. Returns an error string, or None."""
    proc = subprocess.run(
        [str(info.launcher), "--script", str(script)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=runtime.subprocess_env(info), cwd=str(tmp), timeout=config.JOERN_TIMEOUT,
    )
    # A crashed script and a genuine "nothing found" must not look alike. locators.sc ALWAYS
    # writes findings.tsv (empty when clean) and exits 0, so a missing file or a non-zero exit
    # means the locators never ran: the target is UNSCANNED, not clean.
    if proc.returncode != 0 or not out_file.exists():
        summary = _error_summary(proc.stdout or "", proc.stderr or "")
        print("[joern] *** CPG PHASE FAILED - no logic-bug locator ran, target is UNSCANNED ***")
        print(f"[joern]     target={diag.get('target')}  exit={proc.returncode}  "
              f"findings.tsv={'present' if out_file.exists() else 'MISSING'}")
        for ln in summary:
            print(f"[joern]     {ln}")
        return f"cpg phase failed (exit {proc.returncode}): " + " | ".join(summary[-3:])
    return None


def _run_server(srv, rendered: str, proj: str, out_file: Path,
                compile_errors: dict) -> Optional[str]:
    """Server mode: one /query-sync per section. A failing RULE section is recorded and skipped;
    a failing prelude/import/context/finish section aborts (the caller falls back to script
    mode). Returns an error string, or None on success."""
    t_import = config.JOERN_TIMEOUT
    t_rule = max(60, config.JOERN_TIMEOUT // 3)
    try:
        for kind, name, code in _sections(rendered):
            ok, out, err = srv.query(code, timeout=t_import if kind == "import" else t_rule)
            if ok:
                continue
            tail = " | ".join((err or out or "").strip().splitlines()[-3:])[:300]
            if kind == "rule":
                compile_errors[name] = tail
                print(f"[joern]     section 'rule {name}' failed; continuing: {tail[:120]}")
                continue
            if kind == "reverify":                       # P8: informational; the findings stand
                print(f"[joern]     section 'reverify' failed; continuing: {tail[:120]}")
                continue
            return f"server section '{kind}' failed: {tail}"
        if not out_file.exists():
            return "server run finished but findings.tsv is missing"
        return None
    finally:
        # free the CPG project in the long-lived JVM; a failure here must not mask the result
        srv.query('delete("' + proj + '")', timeout=60)


def scan(path: str, pack: str | None = None,
         reverify: tuple[str, str] | None = None) -> tuple[list[Finding], dict]:
    """Build a CPG for `path` and return (candidates, diag). Never raises.
    Uses the server sidecar when it is up (P3), else one `joern --script` per scan.
    `pack` overrides JOERN_PACK for this scan (bench --pack); None means the config value.
    `reverify=(relative_file, method)` (P8) additionally asks the rules to describe that one
    method's guards and sinks; the answer lands in diag["reverify"]."""
    t0 = time.time()
    diag: dict = {"used": False, "reason": "", "elapsed_ms": 0, "candidates": 0,
                  "rules_file": RULES.name, "mode": "script"}
    ok, why, info = runtime.probe()
    if not ok:
        diag["reason"] = why
        return [], diag

    input_dir = os.path.abspath(path)
    diag["target"] = input_dir
    proj = "rampart_" + uuid.uuid4().hex[:12]
    tmp = _scratch_root() / proj
    tmp.mkdir(parents=True, exist_ok=True)
    out_file, diag_file, script = tmp / "findings.tsv", tmp / "diag.json", tmp / "run.sc"
    reverify_out = tmp / "reverify.json" if reverify else None
    compile_errors: dict = {}

    try:
        pack_file, pack_info = prepare_pack(input_dir, pack, tmp)
        diag["pack"] = pack_info
        if pack_file is None:
            diag["reason"] = "vocabulary pack unavailable: " + str(pack_info.get("error"))
            print(f"[joern] {diag['reason']}")
            return [], diag
        if pack_info.get("fallback"):
            print(f"[joern]     pack '{pack_info['resolved']}' rejected -> _base: {pack_info['fallback'][:120]}")
        rendered = _render(input_dir, out_file, diag_file, proj, pack_file, pack_info["tag"],
                           reverify, reverify_out)
        err: Optional[str] = None
        srv = server.ready(wait=float(getattr(config, "JOERN_SERVER_WAIT", 0)))
        if srv is not None:
            diag["mode"] = "server"
            err = _run_server(srv, rendered, proj, out_file, compile_errors)
            if err and not compile_errors:
                # a transport/prelude failure, not a rule: fall back so the scan keeps the phase
                print(f"[joern]     server mode failed ({err[:100]}); falling back to script mode")
                diag["server_fallback"] = err
                diag["mode"] = "script"
                err, srv = None, None
        if srv is None:
            script.write_text(rendered, encoding="utf-8")
            err = _run_script(info, script, tmp, out_file, diag)
        if err:
            diag["reason"] = err
            return [], diag
        out = _collect(out_file, diag_file, input_dir, diag, compile_errors, reverify_out)
        print(f"[joern] ok - {len(out)} candidate(s) from {input_dir} "
              f"in {time.time() - t0:.1f}s [{diag['mode']}, pack {pack_info['tag']}]")
        diag.update(used=True, candidates=len(out))
        return out, diag
    except subprocess.TimeoutExpired:
        diag["reason"] = f"timed out after {config.JOERN_TIMEOUT}s"
        print(f"[joern] {diag['reason']} on {input_dir}")
        return [], diag
    except Exception as e:
        diag["reason"] = f"{type(e).__name__}: {e}"
        print(f"[joern] {diag['reason']}")
        return [], diag
    finally:
        diag["elapsed_ms"] = int((time.time() - t0) * 1000)
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(_workspace_dir() / proj, ignore_errors=True)


def warm() -> None:
    """Start the server sidecar (P3) if allowed; else a fire-and-forget JVM warm-up so the first
    script-mode scan pays less cold start. Best-effort, never raises."""
    if server.ensure_started() is not None:
        return
    ok, _, info = runtime.probe()
    if not ok:
        return
    try:
        subprocess.Popen([str(info.launcher), "--help"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, env=runtime.subprocess_env(info))
    except Exception:
        pass
