"""
RAMPART Knowledge Base - Step 1 (Sources): CrossVul source adapter.

Reads the locally-classified CrossVul corpus (grouped into CWE-named folders) and emits the
universal SourceRecord contract. CrossVul is derived from the HuggingFace dataset
`hitoshura25/crossvul` (Apache-2.0): 9,313 real before/after fix pairs over 158 CWEs and
21 languages. Each report keeps the unified diff of the fix plus the vulnerable lines around
the patched hunk, rather than the whole file.

This is the FIRST source that actually carries a fix, so it is the first to set `fix_ref`.
Downstream, normalize derives `has_fix` from that, which is what makes the `has_fix` Chroma
metadata filter meaningful (HackerOne and Nuclei both leave it false).

Input: data/crossvul_classified/<Weakness>/Report_<pair-id>.md   (9,313 files)
Zero third-party dependencies (stdlib only).
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Iterator, Optional

from .base import SourceAdapter, SourceRecord

ADAPTER_VERSION = "crossvul-adapter/1.0"

_THIS = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DIR = os.path.normpath(os.path.join(_THIS, "..", "..", "data", "crossvul_classified"))

DATASET_URL = "https://huggingface.co/datasets/hitoshura25/crossvul"

# --- header lines (all five are present in 100% of the corpus) ---
_RE_TITLE = re.compile(r"^# CrossVul Fix Pair:\s*(.*)$", re.M)
_RE_PAIR  = re.compile(r"^\*\*Pair ID:\*\*\s*(.*)$", re.M)
_RE_CLASS = re.compile(r"^\*\*Vulnerability Class:\*\*\s*(.*)$", re.M)
_RE_CWE   = re.compile(r"^\*\*CWE:\*\*\s*(CWE-\d+)", re.M)
_RE_LANG  = re.compile(r"^\*\*Language:\*\*\s*(.*)$", re.M)

# Sections are parsed by anchoring on the NEXT KNOWN header rather than on any "## ".
# 11 files in the corpus contain "## " lines inside their fenced code, and a naive
# "(?:\n## |\Z)" terminator truncates the code block at the first one.
_SECTIONS = ("Vulnerability Information & PoC", "Description", "Vulnerable Code",
             "Fix (vulnerable -> fixed)")
_NEXT = "|".join(re.escape(s) for s in _SECTIONS)
_RE_DESC = re.compile(r"^## Description[ \t]*\n(.*?)(?=^## (?:" + _NEXT + r")[ \t]*$|\Z)", re.S | re.M)
_RE_VULN = re.compile(r"^## Vulnerable Code[ \t]*\n(.*?)(?=^## (?:" + _NEXT + r")[ \t]*$|\Z)", re.S | re.M)
_RE_FIX  = re.compile(r"^## Fix \(vulnerable -> fixed\)[ \t]*\n(.*?)(?=^## (?:" + _NEXT + r")[ \t]*$|\Z)", re.S | re.M)

_RE_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
# The processing step prefixes the excerpt with a provenance line we keep out of the code body.
_RE_LINES_NOTE = re.compile(r"^Lines\s+\d+-\d+\s+of the vulnerable file\.\s*\n", re.M)


def _section(rx, text: str) -> str:
    m = rx.search(text)
    return m.group(1).strip() if m else ""


def _first_fence(block: str) -> str:
    m = _RE_FENCE.search(block)
    return m.group(1).strip() if m else ""


class CrossVulAdapter(SourceAdapter):
    source_name = "crossvul"

    def __init__(self, base_dir: str = DEFAULT_DIR, thin_body_threshold: int = 40):
        self.dir = base_dir
        self.thin_body_threshold = thin_body_threshold

    def _iter_files(self):
        for folder in sorted(os.listdir(self.dir)):
            fdir = os.path.join(self.dir, folder)
            if not os.path.isdir(fdir):
                continue
            for fn in sorted(os.listdir(fdir)):
                if fn.endswith(".md"):
                    yield folder, os.path.join(fdir, fn), fn

    def count(self) -> int:
        return sum(1 for _ in self._iter_files())

    def iter_records(self) -> Iterator[SourceRecord]:
        for folder, path, fn in self._iter_files():
            rec = self._parse(folder, path, fn)
            if rec is not None:
                yield rec

    def _parse(self, folder: str, path: str, fn: str) -> Optional[SourceRecord]:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                c = fh.read()
        except OSError:
            return None

        stem = os.path.splitext(fn)[0]                      # "Report_1020_0"
        m = _RE_PAIR.search(c)
        pair_id = (m.group(1).strip() if m else "")
        if not pair_id:
            pair_id = stem[len("Report_"):] if stem.startswith("Report_") else stem

        mt = _RE_TITLE.search(c)
        title = mt.group(1).strip() if mt else folder
        # the "# CrossVul Fix Pair: <...>" line is the natural title; prefix it so the
        # title-prefixed embed_text reads as a security record rather than a bare class name.
        if title and not title.lower().startswith("crossvul"):
            title = f"CrossVul fix pair: {title}"

        file_cwe = (_RE_CWE.search(c).group(1).strip() if _RE_CWE.search(c) else "")
        ml = _RE_LANG.search(c)
        language = ml.group(1).strip().lower() if ml else ""

        description = _section(_RE_DESC, c)
        vuln_block = _section(_RE_VULN, c)
        fix_block = _section(_RE_FIX, c)

        vuln_code = _RE_LINES_NOTE.sub("", _first_fence(vuln_block)).strip()
        fix_diff = _first_fence(fix_block).strip()

        # Code blocks carry this source's real signal: the vulnerable excerpt and the patch.
        code_blocks = [b for b in (vuln_code, fix_diff) if b]

        flags = {
            "is_thin": len(description.strip()) < self.thin_body_threshold,
            "has_redaction": "█" in c,
            "lang_guess": "en",
            "is_non_english": False,
            "is_uncategorized": folder == "Uncategorized",
        }

        source_meta = {
            "program": "",            # not applicable to CrossVul
            "upvotes": "",
            "bounty": "",
            "pair_id": pair_id,
            "code_language": language,
            "file_cwe": file_cwe,
            "dataset": "hitoshura25/crossvul",
            "cwe_method": "crossvul-native",
            "cwe_confidence": "high" if file_cwe else "",
        }

        try:
            retrieved_at = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat()
        except OSError:
            retrieved_at = None

        provenance = {
            "source_file_path": os.path.relpath(path, self.dir).replace("\\", "/"),
            "folder": folder,
            "adapter_version": ADAPTER_VERSION,
            "retrieved_at": retrieved_at,
        }

        return SourceRecord(
            source=self.source_name,
            source_id=pair_id,
            uid=f"{self.source_name}:{pair_id}",
            url=DATASET_URL,
            title=title,
            raw_weakness=folder,
            body=description,
            discussion="",
            code_blocks=code_blocks,
            raw_severity=None,               # CrossVul carries no severity
            # CrossVul IS fix data: every record ships the unified diff of the real fix.
            fix_ref=(f"crossvul:{pair_id}#fix" if fix_diff else None),
            source_meta=source_meta,
            provenance=provenance,
            flags=flags,
        )
