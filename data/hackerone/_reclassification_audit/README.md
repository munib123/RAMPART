# Uncategorized → CWE Reclassification Audit

Date: 2026-07-09

## What this is
The `hackerone_classified/Uncategorized/` folder held **1,202** reports whose
HackerOne JSON `weakness` field was null (and which are also blank-`vuln_type`
in `temp_raw_repo/data.csv`). This run assigned each a CWE weakness folder using
RAMPART's own tiered normalization method (**regex → LLM → adversarial vote**),
then moved the file into the matching existing folder and rewrote its in-file
`**Vulnerability Class:**` line to match.

## Result
- Reports moved into a CWE folder: **1,090**
- Kept in `Uncategorized/`: **112**
  (33 h1-CTF "Hacky Holidays" write-ups, 2 test/placeholder posts,
   1 prototype-pollution [no folder in taxonomy], 76 genuinely ambiguous
   where three independent classifiers disagreed).
- Total `.md` files before/after: **12,061 / 12,061** (no data lost).
- Only files inside `Uncategorized/` were touched; no other folder's contents changed.

## Method (tiers)
1. **Tier-1 regex** (high-precision keyword rules) → 252 unambiguous technical
   classes (XSS sub-types, SQLi, SSRF, CSRF, CRLF, memory-safety natives, etc.).
2. **Tier-2 LLM** → 950 semantically-ambiguous residual, classified against the
   fixed set of existing folder names (may return `Uncategorized`).
3. **Tier-3 adversarial vote** → the 281 low-confidence / Uncategorized cases were
   re-classified by two more independent voters (precise + skeptic lenses); the
   final label is the majority of the 3 votes. No majority → left in `Uncategorized`.

## Files
- `final_mapping.csv` — every report id → chosen folder, method, confidence, reason, title.
- `move_log.csv` — every file move actually performed (id, file, from, to, action, method, confidence).
- `tier1_regex_assignments.csv` — the deterministic Tier-1 output.

## Reversal
To undo: for each row in `move_log.csv` with action `MOVED`, move
`<to>/<file>` back to `Uncategorized/<file>` and reset the class line to
`**Vulnerability Class:** Uncategorized`.
