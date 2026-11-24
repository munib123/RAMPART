"""S3: stage timings in the report and scanner/Joern reuse on an unchanged tree.
The scanner, Joern, RAG and Gemini layers are faked; only the pipeline + cache are real.
Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_timings.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config                       # noqa: E402
from app.services import pipeline            # noqa: E402
from app.services.scanner import Finding     # noqa: E402


class FakeScanner:
    name = "bandit"
    config = ""

    def __init__(self):
        self.calls = 0

    def available(self):
        return True, ""

    def scan(self, path):
        self.calls += 1
        return [Finding(
            tool="bandit", rule_id="B101", title="assert used", path=str(Path(path) / "app.py"),
            line=1, end_line=1, severity="high", confidence="high", cwe_id="CWE-703",
            message="assert used",
        )]


def _project(tmp_path: Path) -> Path:
    target = tmp_path / "proj"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    return target


def _setup(monkeypatch, tmp_path: Path) -> FakeScanner:
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config, "SCAN_CACHE", True)
    monkeypatch.setattr(config, "PROFILE", False)

    scanner = FakeScanner()
    monkeypatch.setattr(pipeline, "get_scanner", lambda name: scanner)
    monkeypatch.setattr(pipeline.joern_scan, "enabled", lambda path: (False, "joern-off"))
    monkeypatch.setattr(pipeline.joern_scan, "rules_sha256", lambda: "rules-test")
    monkeypatch.setattr(pipeline.rag, "retrieve_many", lambda queries: [[] for _ in queries])
    monkeypatch.setattr(pipeline.gemini, "analyze_batch",
                        lambda items, scope: [{"available": True, "verdict": "Likely",
                                               "confidence": 60} for _ in items])
    monkeypatch.setattr(pipeline.gemini, "available", lambda: False)
    return scanner


def test_report_has_every_stage_timing(monkeypatch, tmp_path):
    target = _project(tmp_path)
    _setup(monkeypatch, tmp_path)

    report = pipeline.run_scan(str(target))

    assert report["ok"] is True
    for stage in ("scan", "joern", "extract", "rag", "rank", "total"):
        assert stage in report["timings"], f"missing timings.{stage}"
        assert report["timings"][stage] >= 0
    assert report["timings"]["total"] >= report["timings"]["extract"]


def test_second_scan_reuses_raw_findings(monkeypatch, tmp_path):
    target = _project(tmp_path)
    scanner = _setup(monkeypatch, tmp_path)

    first = pipeline.run_scan(str(target))
    second = pipeline.run_scan(str(target))

    assert scanner.calls == 1                       # scanner subprocess skipped on the second run
    assert not first["joern"].get("cache_hit")
    assert second["joern"].get("cache_hit") is True
    assert second["joern"]["elapsed_ms"] == 0
    assert len(second["findings"]) == len(first["findings"])


def test_fresh_bypasses_the_cache(monkeypatch, tmp_path):
    target = _project(tmp_path)
    scanner = _setup(monkeypatch, tmp_path)

    pipeline.run_scan(str(target))
    pipeline.run_scan(str(target), fresh=True)

    assert scanner.calls == 2


def test_editing_a_file_invalidates_the_cache(monkeypatch, tmp_path):
    target = _project(tmp_path)
    scanner = _setup(monkeypatch, tmp_path)

    pipeline.run_scan(str(target))
    (target / "app.py").write_text("y = 2\n", encoding="utf-8")
    pipeline.run_scan(str(target))

    assert scanner.calls == 2


def test_profile_logs_one_line_per_stage(monkeypatch, tmp_path, capsys):
    target = _project(tmp_path)
    _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(config, "PROFILE", True)

    pipeline.run_scan(str(target))

    out = capsys.readouterr().out
    for stage in ("scan", "joern", "extract", "rag", "rank", "total"):
        assert f"[profile] {stage}" in out
