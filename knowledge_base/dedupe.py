"""
Stage c helper — near-duplicate detection via MinHash + LSH (stdlib only, deterministic).

Deterministic: uses zlib.crc32 (stable across runs, unlike Python's salted hash()).
Conservative by design: a candidate pair is only merged if its ACTUAL shingle Jaccard
>= `threshold` (default 0.90), so distinct-but-similar reports are NOT collapsed.
"""
from __future__ import annotations

import re
import zlib
from typing import Iterable

_WORD = re.compile(r"\w+", re.UNICODE)
_PRIME = 4294967311  # smallest prime > 2**32
_MASK = 0xFFFFFFFF


def shingles(text: str, k: int = 5, cap_tokens: int = 800) -> set[int]:
    """k-word shingles hashed to 32-bit ints. Long docs are capped for speed."""
    toks = _WORD.findall((text or "").lower())[:cap_tokens]
    if not toks:
        return set()
    if len(toks) < k:
        return {zlib.crc32(" ".join(toks).encode("utf-8")) & _MASK}
    return {zlib.crc32(" ".join(toks[i:i + k]).encode("utf-8")) & _MASK
            for i in range(len(toks) - k + 1)}


def _perms(p: int) -> list[tuple[int, int]]:
    """Deterministic (a, b) coefficients for p hash permutations."""
    out = []
    a, b = 1, 1
    for i in range(p):
        a = (a * 6364136223846793005 + 1442695040888963407) & _MASK
        b = (b * 2862933555777941757 + 3037000493) & _MASK
        out.append(((a | 1) & _MASK, b & _MASK))  # a must be odd/non-zero
    return out


def signature(sh: set[int], perms: list[tuple[int, int]]) -> tuple[int, ...]:
    if not sh:
        return tuple([0] * len(perms))
    return tuple(min(((a * h + b) % _PRIME) for h in sh) for a, b in perms)


class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def find_duplicate_clusters(
    texts: list[str],
    num_perm: int = 64,
    bands: int = 16,
    threshold: float = 0.90,
) -> list[int]:
    """
    Return a cluster id per document; documents with the same id are near-duplicates.
    bands * rows == num_perm.  LSH proposes candidates; actual Jaccard confirms.
    """
    rows = num_perm // bands
    perms = _perms(num_perm)
    sh_sets = [shingles(t) for t in texts]
    sigs = [signature(s, perms) for s in sh_sets]

    # LSH: bucket by each band; collect candidate pairs
    uf = _UF(len(texts))
    for band in range(bands):
        buckets: dict[tuple, list[int]] = {}
        lo = band * rows
        for i, sig in enumerate(sigs):
            key = sig[lo:lo + rows]
            buckets.setdefault(key, []).append(i)
        for members in buckets.values():
            if len(members) < 2:
                continue
            base = members[0]
            for j in members[1:]:
                # confirm with actual Jaccard (conservative)
                a, b = sh_sets[base], sh_sets[j]
                if not a or not b:
                    continue
                jac = len(a & b) / len(a | b)
                if jac >= threshold:
                    uf.union(base, j)

    return [uf.find(i) for i in range(len(texts))]
