"""
Source registry — maps a source name to its adapter, output dir, and Chroma collections.
Stages b-e are source-agnostic; only this table changes when a new adapter is added.
"""
import os

from adapters import HackerOneAdapter, NucleiAdapter, CrossVulAdapter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

SOURCES = {
    # HackerOne outputs already live at out/ (root) from the first build — keep them there.
    "hackerone": {
        "adapter": HackerOneAdapter,
        "outdir": OUT,
        "collection_minilm": "rampart_hackerone_minilm",
        "collection_gte": "rampart_hackerone",
    },
    "nuclei": {
        "adapter": NucleiAdapter,
        "outdir": os.path.join(OUT, "nuclei"),
        "collection_minilm": "rampart_nuclei_minilm",
        "collection_gte": "rampart_nuclei",
    },
    # CrossVul (HuggingFace hitoshura25/crossvul): real before/after fix pairs. The only
    # source that supplies fix_ref, so the only one whose records carry has_fix = true.
    "crossvul": {
        "adapter": CrossVulAdapter,
        "outdir": os.path.join(OUT, "crossvul"),
        "collection_minilm": "rampart_crossvul_minilm",
        "collection_gte": "rampart_crossvul",
    },
}


def get_source(name: str) -> dict:
    if name not in SOURCES:
        raise SystemExit(f"unknown source '{name}'. known: {', '.join(SOURCES)}")
    cfg = dict(SOURCES[name])
    cfg["name"] = name
    os.makedirs(cfg["outdir"], exist_ok=True)
    return cfg
