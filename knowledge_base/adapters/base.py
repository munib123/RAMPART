"""
RAMPART Knowledge Base — Step 1 (Sources): the pluggable adapter contract.

Every data source (HackerOne now; CVE, GHSA, OWASP, SecLists later) is wrapped by a
SourceAdapter that emits a stream of SourceRecord objects. Steps b–e of the pipeline
(Normalize -> Dedupe+gate -> Chunk+embed -> Store) bind ONLY to this contract, never
to a specific source, which is what makes new adapters cheap to add.

Design rule for Step 1: extract faithfully, carry provenance + flags, and DECIDE NOTHING.
CWE-ID resolution, severity unification, deep cleaning, dedupe, chunking and embedding
are all deferred to later stages.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Iterator, Optional
import json


@dataclass
class SourceRecord:
    """The universal record every adapter emits (one per raw source item)."""

    # --- identity ---
    source: str                 # adapter id, e.g. "hackerone"
    source_id: str              # native id within the source, e.g. "3723458"
    uid: str                    # globally unique id, e.g. "hackerone:3723458"
    url: str                    # canonical link back to the source item

    # --- content (leaner HN-honest schema: only what actually exists) ---
    title: str
    raw_weakness: str           # the source's own class label (HN: the folder / class tag)
    body: str                   # main technical content (PoC / description)
    discussion: str = ""        # secondary content (timeline / comments), optional
    code_blocks: list[str] = field(default_factory=list)  # fenced code, only if present

    # --- raw signals the source may or may not provide ---
    raw_severity: Optional[str] = None   # source severity if any (HN markdown: None)
    fix_ref: Optional[str] = None        # link/commit to a fix if provided (HN: usually None)

    # --- source-specific extras + provenance + downstream flags ---
    source_meta: dict = field(default_factory=dict)   # e.g. program, upvotes, bounty, cwe_method, confidence
    provenance: dict = field(default_factory=dict)    # source_file_path, adapter_version, retrieved_at
    flags: dict = field(default_factory=dict)         # is_thin, has_redaction, lang_guess, is_non_english

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class SourceAdapter(ABC):
    """Abstract base every source adapter implements. Keep it tiny on purpose."""

    #: short, stable identifier for the source (used in uid / metadata)
    source_name: str = "base"

    @abstractmethod
    def count(self) -> int:
        """Total number of raw items this adapter will yield (for progress/UX)."""
        raise NotImplementedError

    @abstractmethod
    def iter_records(self) -> Iterator[SourceRecord]:
        """Stream SourceRecord objects. MUST be lazy so large sources never load at once."""
        raise NotImplementedError
