# RAMPART — Knowledge Base pipeline

Offline pipeline that turns disclosed-vulnerability sources into a retrievable corpus:

```
a. Sources  ->  b. Normalize  ->  c. Dedupe+gate  ->  d. Chunk+embed  ->  e. Dual store
```

Every source is wrapped by a **pluggable adapter** (Step 1) that emits one universal
`SourceRecord` contract; stages b–e bind only to that contract, never to a specific source.

**Sources wired so far** (`sources.py`): `hackerone` (12,061 reports) · `nuclei` (5,308 CVE
templates). Adding a source = one adapter in `adapters/` + one row in `sources.py`.

## Multi-source runner

```bash
python run_pipeline.py --source nuclei --stages normalize,gate,chunk,embed --backend minilm-onnx --reset
python run_pipeline.py --source nuclei --query "sql injection in id param" --cwe CWE-89
```
Outputs land in `out/<source>/` (HackerOne's are at `out/` root for historical reasons);
each source gets its own Chroma collection (`rampart_<source>_minilm`).

## Implemented so far

- **Stage a — Sources** (`adapters/base.py`, `adapters/hackerone.py`): `SourceAdapter` (ABC) +
  `SourceRecord` (universal contract); `HackerOneAdapter` reads the corpus and streams records.
- **Stage b — Normalize** (`adapters/normalize.py`): `Normalizer` cleans text (protecting code),
  attaches CWE ids from `adapters/weakness_to_cwe.json`, sets severity/has_fix, and produces
  `NormalizedRecord`. Non-English records are translated and merged in.

```python
from adapters import HackerOneAdapter, Normalizer

ad, nz = HackerOneAdapter(), Normalizer()
print(ad.count())                       # 12061
for rec in ad.iter_records():           # lazy / streaming SourceRecord
    nr = nz.normalize(rec)              # -> NormalizedRecord
```

## Run (full pipeline a → d)

```bash
python run_adapter.py                    # a  : source summary
python run_normalize.py                  # b  : -> out/normalized.jsonl (+ translation batches)
python merge_translations.py             # b  : apply English translations
python run_stage_c.py                    # c  : dedupe + gate -> out/gated.jsonl
python run_stage_d_chunk.py              # d.1: section chunk  -> out/chunks.jsonl
python run_stage_d_embed.py --backend minilm-onnx --reset   # d.2: embed -> ChromaDB
```

Outputs: `out/normalized.jsonl` (12,061) → `out/gated.jsonl` (9,352) → `out/chunks.jsonl`
(30,818) → `out/chroma/` (ChromaDB collection).

## Query the RAG store

```bash
python run_stage_d_embed.py --backend minilm-onnx --query "SSRF to internal metadata" --cwe CWE-918
```

## Embedding backends
- `gte`  — **production**: `Alibaba-NLP/gte-large-en-v1.5` (1024-dim), needs torch+GPU (run on the 4090).
- `minilm-onnx` — **torch-free placeholder** shipped now (all-MiniLM-L6-v2, 384-dim) via ChromaDB's
  bundled ONNX runtime. Same pipeline; swap the backend + re-embed when the GPU box is ready.

## Locked stack for the HackerOne adapter

Embedding `Alibaba-NLP/gte-large-en-v1.5` (1024-dim, 8k ctx) · section-based chunks ·
leaner HN-honest schema · Chroma-first (Postgres later).

Full end-to-end lineage for this source:
[`../Data/HAckerone/HACKERONE_SOURCE.md`](../Data/HAckerone/HACKERONE_SOURCE.md).
