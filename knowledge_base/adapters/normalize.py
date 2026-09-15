"""
RAMPART Knowledge Base — Stage b (Normalize).

SourceRecord (raw, from an adapter)  ->  NormalizedRecord (clean, leaner HN-honest schema).

What this stage does:
  - clean prose (strip redaction blocks, HackerOne file tokens, raw HTML, entities, whitespace)
    WITHOUT touching fenced code blocks;
  - attach cwe_id / cwe_name / cwe_category from the weakness->CWE table;
  - set severity = "unknown", has_fix = False (HackerOne provides neither reliably);
  - compute a richer `is_thin` (body + discussion) so Stage c can gate on real emptiness;
  - carry English text in `title` / `description`; when the source was non-English and a
    translation is supplied, keep the source-language text in `*_original`.

Translation itself is done by a separate LLM pass; `apply_translations()` merges it back in.
"""
from __future__ import annotations

import html
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Iterator, Optional

from .base import SourceRecord

_THIS = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CWE_MAP = os.path.join(_THIS, "weakness_to_cwe.json")

_RE_FENCE_SPLIT = re.compile(r"(```.*?```)", re.S)
_RE_REDACTION = re.compile(r"[█░▒▓]+")   # █ ░ ▒ ▓ runs
_RE_HN_FILE = re.compile(r"\{F\d+\}")                        # HackerOne attachment tokens
_RE_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")           # markdown images
_RE_HTML_TAG = re.compile(r"<[^>\n]{1,200}?>")               # conservative raw-tag strip (prose only)
_RE_WS = re.compile(r"[ \t]+")
_RE_BLANKS = re.compile(r"\n{3,}")

THIN_THRESHOLD = 40

_SEV_MAP = {
    "critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
    "low": "low", "info": "info", "informational": "info", "none": "unknown", "unknown": "unknown",
}


def norm_severity(raw) -> str:
    """Normalize a source-provided severity to a fixed vocabulary; 'unknown' if absent."""
    if not raw:
        return "unknown"
    return _SEV_MAP.get(str(raw).strip().lower(), "unknown")


def _clean_prose(text: str) -> str:
    text = _RE_REDACTION.sub("[REDACTED]", text)
    text = _RE_HN_FILE.sub("", text)
    text = _RE_MD_IMAGE.sub("", text)
    text = _RE_HTML_TAG.sub("", text)      # strip tags BEFORE unescaping so entities can't form new tags
    text = html.unescape(text)
    text = _RE_WS.sub(" ", text)
    text = _RE_BLANKS.sub("\n\n", text)
    return text.strip()


def clean_text(text: str) -> str:
    """Clean prose but leave fenced code blocks byte-for-byte intact."""
    if not text:
        return ""
    out = []
    for part in _RE_FENCE_SPLIT.split(text):
        if part.startswith("```"):
            out.append(part)                 # preserve code exactly
        else:
            out.append(_clean_prose(part))
    return "".join(out).strip()


@dataclass
class NormalizedRecord:
    uid: str
    source: str
    source_id: str
    url: str

    title: str                       # English (translated if needed)
    description: str                 # English (translated if needed) — the PoC / description
    discussion: str = ""
    code_blocks: list[str] = field(default_factory=list)

    weakness_label: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    cwe_category: str = ""            # cwe | owasp-llm | owasp-asi | uncategorized

    severity: str = "unknown"
    has_fix: bool = False
    lang: str = "en"
    translated: bool = False
    title_original: Optional[str] = None
    description_original: Optional[str] = None

    metadata: dict = field(default_factory=dict)   # program, upvotes, bounty, cwe_method, cwe_confidence, source_file_path
    flags: dict = field(default_factory=dict)       # is_thin, has_code, is_uncategorized, has_redaction

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class Normalizer:
    def __init__(self, cwe_map_path: str = DEFAULT_CWE_MAP):
        self.cwe_map = self._load_map(cwe_map_path)

    @staticmethod
    def _load_map(path: str) -> dict:
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"weakness->CWE map not found at {path}. Generate it before running Stage b."
            )
        raw = json.load(open(path, encoding="utf-8"))
        # accept either {weakness: {...}} or [{weakness,...}]
        if isinstance(raw, list):
            return {r["weakness"]: r for r in raw}
        return raw

    def normalize(self, rec: SourceRecord) -> NormalizedRecord:
        title = clean_text(rec.title)
        description = clean_text(rec.body)
        discussion = clean_text(rec.discussion)

        m = self.cwe_map.get(rec.raw_weakness, {})
        lang = rec.flags.get("lang_guess", "en")

        content_len = len(description) + len(discussion)
        flags = {
            "is_thin": content_len < THIN_THRESHOLD,
            "has_code": bool(rec.code_blocks),
            "is_uncategorized": rec.raw_weakness == "Uncategorized",
            "has_redaction": bool(rec.flags.get("has_redaction")),
        }

        return NormalizedRecord(
            uid=rec.uid,
            source=rec.source,
            source_id=rec.source_id,
            url=rec.url,
            title=title,
            description=description,
            discussion=discussion,
            code_blocks=list(rec.code_blocks),
            weakness_label=rec.raw_weakness,
            cwe_id=m.get("cwe_id", ""),
            cwe_name=m.get("cwe_name", ""),
            cwe_category=m.get("category", ""),
            severity=norm_severity(rec.raw_severity),
            # Derived, not hardcoded: a source that supplies a fix reference (CrossVul ships
            # the real unified diff) makes has_fix true, which is what the metadata filter is
            # for. HackerOne and Nuclei leave fix_ref None, so they stay false exactly as before.
            has_fix=bool(rec.fix_ref),
            lang=lang,
            translated=False,
            metadata={
                "program": rec.source_meta.get("program", ""),
                "upvotes": rec.source_meta.get("upvotes", ""),
                "bounty": rec.source_meta.get("bounty", ""),
                "cwe_method": rec.source_meta.get("cwe_method", ""),
                "cwe_confidence": rec.source_meta.get("cwe_confidence", ""),
                "source_file_path": rec.provenance.get("source_file_path", ""),
            },
            flags=flags,
        )

    def normalize_all(self, records: Iterator[SourceRecord]) -> Iterator[NormalizedRecord]:
        for rec in records:
            yield self.normalize(rec)


def apply_translation(nr: NormalizedRecord, title_en: str, description_en: str) -> None:
    """Merge an English translation into a record, preserving the source-language text."""
    nr.title_original = nr.title
    nr.description_original = nr.description
    nr.title = title_en.strip() or nr.title
    nr.description = description_en.strip() or nr.description
    nr.translated = True
