"""RAMPART knowledge-base source adapters + normalizer (Steps a-b)."""
from .base import SourceAdapter, SourceRecord
from .hackerone import HackerOneAdapter
from .nuclei import NucleiAdapter
from .crossvul import CrossVulAdapter
from .normalize import Normalizer, NormalizedRecord, clean_text, apply_translation, norm_severity

__all__ = [
    "SourceAdapter", "SourceRecord", "HackerOneAdapter", "NucleiAdapter", "CrossVulAdapter",
    "Normalizer", "NormalizedRecord", "clean_text", "apply_translation", "norm_severity",
]
