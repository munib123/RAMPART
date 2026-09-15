"""
RAMPART Knowledge Base — Step 1 (Sources): HackerOne source adapter.

Reads the locally-materialised HackerOne corpus produced by the earlier fetch +
reclassification work and emits the universal SourceRecord contract.

Inputs (all already on disk, nothing is fetched here):
  - hackerone_classified/<Weakness>/Report_<id>.md   (12,061 reports)
  - temp_raw_repo/data.csv                            (join: program, upvotes, bounty, url)
  - _reclassification_audit/final_mapping.csv         (join: cwe_method, confidence provenance)

Zero third-party dependencies (stdlib only) so it runs immediately.
"""
from __future__ import annotations

import csv
import os
import re
from datetime import datetime, timezone
from typing import Iterator, Optional

from .base import SourceAdapter, SourceRecord

ADAPTER_VERSION = "hackerone-adapter/1.0"

# Default layout under D:\FYP\Data\HAckerone\data
_THIS = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASE = os.path.normpath(os.path.join(_THIS, "..", "..", "data", "hackerone"))

# --- parsing patterns (the markdown template the fetcher wrote) ---
_RE_TITLE   = re.compile(r"^# HackerOne Report:\s*(.*)$", re.M)
_RE_ID      = re.compile(r"^\*\*Report ID:\*\*\s*(\d+)\s*$", re.M)
_RE_CLASS   = re.compile(r"^\*\*Vulnerability Class:\*\*\s*(.*)$", re.M)
# NOTE: consume only the header's own line-ending ([ \t]*\n) and use a zero-width
# lookahead for the next section, so an EMPTY PoC body doesn't swallow the Discussion header.
_RE_BODY    = re.compile(r"## Vulnerability Information & PoC[ \t]*\n(.*?)(?=\n## Discussion & Remediation Timeline|\Z)", re.S)
_RE_DISC    = re.compile(r"## Discussion & Remediation Timeline\s*\n(.*)\Z", re.S)
_RE_FENCE   = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_RE_FILEID  = re.compile(r"Report_(\d+)\.md$")
_RE_LINKID  = re.compile(r"reports/(\d+)")

_REDACTION_CHARS = "█░▒▓"


def _guess_lang(text: str) -> tuple[str, bool]:
    """Coarse, dependency-free language guess. Enough to FLAG non-English for step b/c."""
    cyr = sum(1 for c in text if 0x0400 <= ord(c) <= 0x04FF)
    cjk = sum(1 for c in text if 0x4E00 <= ord(c) <= 0x9FFF)
    arab = sum(1 for c in text if 0x0600 <= ord(c) <= 0x06FF)
    if cyr >= 3:
        return "ru", True
    if cjk >= 3:
        return "cjk", True
    if arab >= 3:
        return "ar", True
    return "en", False


class HackerOneAdapter(SourceAdapter):
    source_name = "hackerone"

    def __init__(
        self,
        base_dir: str = DEFAULT_BASE,
        classified_dir: Optional[str] = None,
        data_csv: Optional[str] = None,
        mapping_csv: Optional[str] = None,
        include_uncategorized: bool = True,
        thin_body_threshold: int = 40,
    ):
        self.classified_dir = classified_dir or os.path.join(base_dir, "hackerone_classified")
        self.data_csv = data_csv if data_csv is not None else os.path.join(base_dir, "temp_raw_repo", "data.csv")
        self.mapping_csv = mapping_csv if mapping_csv is not None else os.path.join(base_dir, "_reclassification_audit", "final_mapping.csv")
        self.include_uncategorized = include_uncategorized
        self.thin_body_threshold = thin_body_threshold

        self._data = self._load_data_csv(self.data_csv)          # id -> {program, upvotes, bounty, url}
        self._mapping = self._load_mapping_csv(self.mapping_csv)  # id -> {cwe_method, confidence}

    # ---------- side tables ----------
    @staticmethod
    def _load_data_csv(path: str) -> dict:
        out: dict = {}
        if not path or not os.path.isfile(path):
            return out
        with open(path, encoding="utf-8", errors="ignore", newline="") as fh:
            for row in csv.DictReader(fh):
                m = _RE_LINKID.search(row.get("link", "") or "")
                if not m:
                    continue
                out[m.group(1)] = {
                    "program": (row.get("program") or "").strip(),
                    "upvotes": (row.get("upvotes") or "").strip(),
                    "bounty": (row.get("bounty") or "").strip(),
                    "url": (row.get("link") or "").strip(),
                }
        return out

    @staticmethod
    def _load_mapping_csv(path: str) -> dict:
        out: dict = {}
        if not path or not os.path.isfile(path):
            return out
        with open(path, encoding="utf-8", errors="ignore", newline="") as fh:
            for row in csv.DictReader(fh):
                rid = (row.get("id") or "").strip()
                if not rid:
                    continue
                out[rid] = {
                    "cwe_method": (row.get("method") or "").strip(),
                    "cwe_confidence": (row.get("confidence") or "").strip(),
                }
        return out

    # ---------- SourceAdapter API ----------
    def count(self) -> int:
        n = 0
        for _ in self._iter_files():
            n += 1
        return n

    def _iter_files(self):
        for folder in sorted(os.listdir(self.classified_dir)):
            fdir = os.path.join(self.classified_dir, folder)
            if not os.path.isdir(fdir):
                continue
            if folder == "Uncategorized" and not self.include_uncategorized:
                continue
            for fn in sorted(os.listdir(fdir)):
                if _RE_FILEID.search(fn):
                    yield folder, os.path.join(fdir, fn), fn

    def iter_records(self) -> Iterator[SourceRecord]:
        for folder, path, fn in self._iter_files():
            rec = self._parse_file(folder, path, fn)
            if rec is not None:
                yield rec

    # ---------- parsing ----------
    def _parse_file(self, folder: str, path: str, fn: str) -> Optional[SourceRecord]:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            return None

        # id: prefer the in-file tag, fall back to the filename
        m_id = _RE_ID.search(content)
        m_fn = _RE_FILEID.search(fn)
        source_id = (m_id.group(1) if m_id else (m_fn.group(1) if m_fn else "")).strip()
        if not source_id:
            return None

        m_title = _RE_TITLE.search(content)
        title = (m_title.group(1).strip() if m_title else "").strip()

        m_class = _RE_CLASS.search(content)
        # the in-file class tag and the folder name should agree post-reclassification;
        # trust the folder as the authoritative label, keep the tag only as a fallback.
        raw_weakness = folder if folder else (m_class.group(1).strip() if m_class else "Uncategorized")

        m_body = _RE_BODY.search(content)
        body = (m_body.group(1).strip() if m_body else "")

        m_disc = _RE_DISC.search(content)
        discussion = (m_disc.group(1).strip() if m_disc else "")

        code_blocks = [b.strip() for b in _RE_FENCE.findall(content) if b.strip()]

        meta = self._data.get(source_id, {})
        url = meta.get("url") or f"hackerone.com/reports/{source_id}"
        source_meta = {
            "program": meta.get("program", ""),
            "upvotes": meta.get("upvotes", ""),
            "bounty": meta.get("bounty", ""),
        }
        source_meta.update(self._mapping.get(source_id, {"cwe_method": "hackerone-native", "cwe_confidence": ""}))

        full_text = f"{title}\n{body}"
        lang_guess, is_non_english = _guess_lang(full_text)
        flags = {
            "is_thin": len(body.strip()) < self.thin_body_threshold,
            "has_redaction": any(c in content for c in _REDACTION_CHARS),
            "lang_guess": lang_guess,
            "is_non_english": is_non_english,
            "is_uncategorized": raw_weakness == "Uncategorized",
        }

        try:
            retrieved_at = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat()
        except OSError:
            retrieved_at = None

        provenance = {
            "source_file_path": os.path.relpath(path, self.classified_dir).replace("\\", "/"),
            "folder": folder,
            "adapter_version": ADAPTER_VERSION,
            "retrieved_at": retrieved_at,
        }

        return SourceRecord(
            source=self.source_name,
            source_id=source_id,
            uid=f"{self.source_name}:{source_id}",
            url=url,
            title=title,
            raw_weakness=raw_weakness,
            body=body,
            discussion=discussion,
            code_blocks=code_blocks,
            raw_severity=None,   # HackerOne markdown carries no severity; decided later
            fix_ref=None,        # HackerOne rarely provides a fix commit -> has_fix=false downstream
            source_meta=source_meta,
            provenance=provenance,
            flags=flags,
        )
