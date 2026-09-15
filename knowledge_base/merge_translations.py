"""
Apply English translations back into out/normalized.jsonl (in place).

Expects out/translations.json = {"results":[{uid,title_en,description_en}, ...]}.
For each translated uid: move original text to *_original, set English into title/description,
mark translated=True.
"""
from __future__ import annotations

import json
import os

from adapters.normalize import clean_text

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
NORM = os.path.join(OUT, "normalized.jsonl")
TRANS = os.path.join(OUT, "translations.json")

MIN_ORIG_DESC = 20  # only translate the body if the ORIGINAL body was real content


def _is_header_echo(text: str) -> bool:
    t = text.strip()
    return t.startswith("## Discussion") or t.startswith("## Vulnerability Information")


def main() -> int:
    raw = json.load(open(TRANS, encoding="utf-8"))
    tlist = raw["results"] if isinstance(raw, dict) and "results" in raw else raw
    tr = {str(t["uid"]): t for t in tlist}

    records = [json.loads(l) for l in open(NORM, encoding="utf-8")]
    applied_title = applied_desc = 0
    for r in records:
        t = tr.get(r["uid"])
        if not t:
            continue
        orig_title = r["title"]
        orig_desc = r["description"]
        r["title_original"] = orig_title
        r["description_original"] = orig_desc

        title_en = clean_text((t.get("title_en") or "").strip())
        if title_en:
            r["title"] = title_en
            applied_title += 1

        # guard: skip hallucinated/echoed descriptions on thin records
        desc_en = clean_text((t.get("description_en") or "").strip())
        if desc_en and len(orig_desc.strip()) >= MIN_ORIG_DESC and not _is_header_echo(desc_en):
            r["description"] = desc_en
            applied_desc += 1

        r["translated"] = True

    with open(NORM, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"records: {len(records)}  translations available: {len(tr)}")
    print(f"  titles translated       : {applied_title}")
    print(f"  descriptions translated : {applied_desc}  (rest were thin/echoed -> kept original)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
