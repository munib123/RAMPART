"""
LocatorBackend: the one interface every arm implements so the harness scores them identically.

    locate(target_dir) -> list[Candidate]     what did this arm report?
    fingerprint()      -> dict                what exactly produced it? (goes into run.json;
                                              a changed fingerprint means a changed behaviour)
    verdict_gated      -> bool                does it produce LLM verdicts? If not, every
                                              candidate counts as reported.

Registry:
    null      reports nothing. The trivial baseline every benchmark needs.
    bandit    app.services.scanner.BanditScanner
    semgrep   app.services.scanner.SemgrepScanner
    joern     app.services.joern.scan - the CPG locator alone, no LLM   (the joern_only arm)
    full      app.services.pipeline.run_scan - everything, verdict-gated

Vocabulary packs (P5): `--pack <id>` pins the pack for the joern and full arms; the pack id and
its sha256 go into the fingerprint next to rules_sha256, so `--pack _base` vs `--pack X` on one
benchmark is the no_vocab_pack ablation with everything else frozen.
"""
from __future__ import annotations

import hashlib
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from bench import paths                      # noqa: F401  (puts backend/ on sys.path)
from bench.match import Candidate


def _sha256_file(p: Path) -> str:
    """Content hash with line endings normalised to LF, so the hash quoted in a run artifact is
    the same on a CRLF (Windows autocrlf) and an LF checkout of the same commit."""
    if not p.is_file():
        return ""
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:16]


def _git_dirty() -> bool:
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=paths.ROOT,
                             capture_output=True, text=True, timeout=10).stdout
        return bool(out.strip())
    except Exception:
        return False


def _git_sha() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=paths.ROOT,
                              capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _pkg_version(name: str) -> str:
    try:
        import importlib.metadata as m
        return m.version(name)
    except Exception:
        return ""


class LocatorBackend(ABC):
    name: str = "base"
    verdict_gated: bool = False

    @abstractmethod
    def locate(self, target_dir: str) -> list[Candidate]: ...

    def fingerprint(self) -> dict:
        return {"backend": self.name, "rampart_git_sha": _git_sha(), "rampart_git_dirty": _git_dirty()}


class NullBackend(LocatorBackend):
    name = "null"

    def locate(self, target_dir: str) -> list[Candidate]:
        return []


def _from_findings(findings) -> list[Candidate]:
    out = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        out.append(Candidate(tool=d["tool"], rule_id=d["rule_id"], path=d["path"],
                             line=int(d["line"]), end_line=int(d.get("end_line") or d["line"]),
                             cwe_id=d.get("cwe_id", ""), meta=dict(d.get("meta") or {})))
    return out


class BanditBackend(LocatorBackend):
    name = "bandit"

    def locate(self, target_dir: str) -> list[Candidate]:
        from app.services.scanner import BanditScanner
        s = BanditScanner()
        ok, why = s.available()
        if not ok:
            raise SystemExit(f"bandit unavailable: {why}")
        return _from_findings(s.scan(target_dir))

    def fingerprint(self) -> dict:
        return {**super().fingerprint(), "bandit": _pkg_version("bandit")}


class SemgrepBackend(LocatorBackend):
    name = "semgrep"

    def locate(self, target_dir: str) -> list[Candidate]:
        from app.services.scanner import SemgrepScanner
        s = SemgrepScanner()
        ok, why = s.available()
        if not ok:
            raise SystemExit(f"semgrep unavailable: {why}")
        return _from_findings(s.scan(target_dir))

    def fingerprint(self) -> dict:
        from app import config
        return {**super().fingerprint(), "semgrep": _pkg_version("semgrep"),
                "semgrep_config": getattr(config, "SEMGREP_CONFIG", "auto"),
                "note": "--config auto fetches registry rules at scan time; not pinned"}


class JoernBackend(LocatorBackend):
    """The CPG locator alone, without the LLM. This is the joern_only ablation arm: what the
    four rules find before anything clears them. Its bait_fp count is the design working as
    intended (find_product) and the number the full arm is expected to drive to zero."""
    name = "joern"

    def __init__(self, pack: str | None = None):
        self.pack = pack

    def locate(self, target_dir: str) -> list[Candidate]:
        from app.services.joern import scan as joern_scan, server as joern_server
        ok, why = joern_scan.enabled(target_dir)
        if not ok:
            raise SystemExit(f"joern unavailable: {why}")
        # P3: use the sidecar when the config allows, so bench timings match the app. The
        # harness has no lifespan hook, so start it here and give it time to come up; scan()
        # falls back to script mode on its own if it does not. atexit stops it.
        srv = joern_server.ensure_started()
        if srv is not None:
            srv.wait_ready(120)
        findings, diag = joern_scan.scan(target_dir, pack=self.pack)
        self._diag = diag
        return _from_findings(findings)

    def fingerprint(self) -> dict:
        from app.services.joern import runtime, scan as joern_scan
        info = runtime.locate()
        return {**super().fingerprint(),
                "joern_version": info.joern_version,
                "mode": getattr(self, "_diag", {}).get("mode"),
                "java_major": info.java_major,
                "rules_file": joern_scan.RULES.name,
                "rules_sha256": _sha256_file(joern_scan.RULES),
                "pack": getattr(self, "_diag", {}).get("pack"),
                "diag": getattr(self, "_diag", {})}


class FullBackend(LocatorBackend):
    """The whole pipeline through pipeline.run_scan: scanner + joern + RAG + LLM verdicts.
    Verdict-gated: only Confirmed/Likely count as reported; Informational/False positive are
    'cleared' and never charged as FP. Without GEMINI_API_KEY every verdict is Unverified, which
    is neither reported nor cleared - the run will show recall 0 and say so in the fingerprint."""
    name = "full"
    verdict_gated = True

    def __init__(self, scanner: str = "auto", scope: dict | None = None, pack: str | None = None):
        self.scanner = scanner
        self.scope = scope or {"platform": "ecommerce", "stack": ["python"],
                               "priorities": ["access-control", "injection"]}
        if pack:                                        # pipeline reads config; pin it for this run
            from app import config
            config.JOERN_PACK = pack

    def locate(self, target_dir: str) -> list[Candidate]:
        from app.services import pipeline
        r = pipeline.run_scan(target_dir, self.scanner, self.scope)
        if not r.get("ok"):
            raise SystemExit(f"pipeline failed: {r.get('error')}")
        self._result = {k: r[k] for k in ("scanner", "joern", "llm", "counts", "elapsed_s")}
        out = []
        for f in r["findings"]:
            v = f.get("verdict") or {}
            out.append(Candidate(tool=f["tool"], rule_id=f["rule_id"], path=f["path"],
                                 line=int(f["line"]), end_line=int(f.get("end_line") or f["line"]),
                                 cwe_id=f.get("cwe_id", ""), verdict=v.get("verdict"),
                                 confidence=v.get("confidence"), meta=dict(f.get("meta") or {})))
        return out

    def fingerprint(self) -> dict:
        from app import config
        from app.services.joern import scan as joern_scan
        fp = {**super().fingerprint(), "scanner": self.scanner, "scope": self.scope,
              "gemini_model": config.GEMINI_MODEL, "llm_enabled": bool(config.GEMINI_API_KEY),
              "rules_sha256": _sha256_file(joern_scan.RULES),
              "collections": list(config.COLLECTIONS), "rag_k": config.RAG_K,
              "llm_batch": config.LLM_BATCH, "max_llm_findings": config.MAX_LLM_FINDINGS,
              "joern_llm_quota": getattr(config, "JOERN_LLM_QUOTA", None),
              "joern_pack_setting": getattr(config, "JOERN_PACK", "auto")}
        fp.update(getattr(self, "_result", {}))
        if isinstance(fp.get("joern"), dict) and fp["joern"].get("pack"):
            fp["pack"] = fp["joern"]["pack"]
        return fp


REGISTRY = {
    "null": NullBackend,
    "bandit": BanditBackend,
    "semgrep": SemgrepBackend,
    "joern": JoernBackend,
    "full": FullBackend,
}


def get_backend(name: str, **kw) -> LocatorBackend:
    if name not in REGISTRY:
        raise SystemExit(f"unknown backend '{name}'. known: {', '.join(REGISTRY)}")
    return REGISTRY[name](**kw)
