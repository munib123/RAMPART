"""
RAMPART Knowledge Base — Step 1 (Sources): Nuclei / CVE source adapter.

Reads the locally-classified Nuclei templates (grouped into CWE-named folders) and emits the
universal SourceRecord contract. Richer than HackerOne: every template carries an explicit
Severity and (usually) a CWE id, and ~75% are named by CVE id.

Input: Data/nuclei_classified/<Weakness>/<template-or-CVE>.md   (5,308 files)
Zero third-party dependencies (stdlib only).
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Iterator, Optional

from .base import SourceAdapter, SourceRecord

ADAPTER_VERSION = "nuclei-adapter/1.0"

_THIS = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DIR = os.path.normpath(os.path.join(_THIS, "..", "..", "Data", "nuclei_classified"))

_RE_TITLE = re.compile(r"^# Nuclei Template:\s*(.*)$", re.M)
_RE_TID   = re.compile(r"^\*\*Template ID:\*\*\s*(.*)$", re.M)
_RE_CLASS = re.compile(r"^\*\*Vulnerability Class:\*\*\s*(.*)$", re.M)
_RE_SEV   = re.compile(r"^\*\*Severity:\*\*\s*(.*)$", re.M)
_RE_CWE   = re.compile(r"^\*\*CWE:\*\*\s*(.*)$", re.M)
_RE_YAML  = re.compile(r"^\*\*Source:\*\*.*?`([^`]+)`", re.M)
_RE_DESC  = re.compile(r"## Description\s*\n(.*?)(?:\n## |\Z)", re.S)
_RE_PAY   = re.compile(r"## Steps to reproduce / Exploit Payload\s*\n(.*?)(?:\n## |\Z)", re.S)
_RE_REF   = re.compile(r"## References\s*\n(.*?)(?:\n## |\Z)", re.S)
_RE_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_RE_CVE   = re.compile(r"CVE-\d{4}-\d+", re.I)


class NucleiAdapter(SourceAdapter):
    source_name = "nuclei"

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

        m = _RE_TID.search(c)
        stem = os.path.splitext(fn)[0]
        template_id = (m.group(1).strip() if m else stem)
        if not template_id:
            template_id = stem

        mt = _RE_TITLE.search(c)
        title = mt.group(1).strip() if mt else ""
        severity = (_RE_SEV.search(c).group(1).strip() if _RE_SEV.search(c) else "")
        file_cwe = (_RE_CWE.search(c).group(1).strip() if _RE_CWE.search(c) else "")
        yaml_src = (_RE_YAML.search(c).group(1).strip() if _RE_YAML.search(c) else "")

        description = (_RE_DESC.search(c).group(1).strip() if _RE_DESC.search(c) else "")
        payload = (_RE_PAY.search(c).group(1).strip() if _RE_PAY.search(c) else "")

        refs = []
        mref = _RE_REF.search(c)
        if mref:
            refs = [ln.strip("- ").strip() for ln in mref.group(1).splitlines() if ln.strip().startswith("-")]

        # code = fenced blocks (mostly the exploit payload)
        code_blocks = [b.strip() for b in _RE_FENCE.findall(c) if b.strip()]

        # cve id: prefer the filename, else scan title/references
        cve = ""
        mcve = _RE_CVE.search(stem) or _RE_CVE.search(title) or _RE_CVE.search(" ".join(refs))
        if mcve:
            cve = mcve.group(0).upper()

        url = (f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else (refs[0] if refs else ""))

        # body = description; the payload lives in code_blocks (and is appended for context)
        body = description
        if payload and "```" not in payload:
            body = (description + "\n\n" + payload).strip()

        flags = {
            "is_thin": len(body.strip()) < self.thin_body_threshold,
            "has_redaction": "█" in c,
            "lang_guess": "en",
            "is_non_english": False,
            "is_uncategorized": folder == "Uncategorized",
        }

        source_meta = {
            "program": "",           # not applicable to Nuclei
            "upvotes": "",
            "bounty": "",
            "template_id": template_id,
            "cve_id": cve,
            "file_cwe": file_cwe,
            "yaml_source": yaml_src,
            "references": " | ".join(refs[:5]),
            "cwe_method": "nuclei-native",
            "cwe_confidence": "",
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
            source_id=template_id,
            uid=f"{self.source_name}:{template_id}",
            url=url,
            title=title,
            raw_weakness=folder,
            body=body,
            discussion="",
            code_blocks=code_blocks,
            raw_severity=severity or None,   # <-- Nuclei DOES carry severity
            fix_ref=None,                    # detection templates, no fix commit
            source_meta=source_meta,
            provenance=provenance,
            flags=flags,
        )
