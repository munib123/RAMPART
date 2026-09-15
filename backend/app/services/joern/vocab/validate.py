"""
Vocabulary packs: load, validate, compose, hash, resolve. Pure stdlib, no JVM.

A pack is the DATA half of a locator rule: the token lists that say what an ownership check,
a lock, an allow-list or an object id look like in a given framework. The Scala in
rules/locators.sc is frozen and hashed; only the pack varies per target. schema.json is the
grammar and this module enforces it - every rule below is a security control (TDD 8.8, T-10):

  * every slot declares its sink and the sink's character class is enforced per value, so a
    value written for String.contains can never reach a regex-taking accessor or Scala source
  * caps: 8 KB per file, 64 values per slot, extends depth 3
  * cross-slot rules: authz_guard never a substring of authn_only; qty/price disjoint; text
    sinks lower-case, SQL keywords upper-case (a wrong-case value could never match: a no-op)
  * composition is a per-slot UNION with the parent, sorted + de-duplicated before hashing, so
    the digest does not depend on author ordering
  * a digest allowlist (packs/digests.json): a shipped pack whose canonical digest is not listed
    is refused; an unlisted pack loads only when the caller says allow_unlisted

Anything failing is discarded WHOLE - the caller falls back to _base and the reason lands in the
scan diag. Nothing here ever raises for a bad pack; `load()` returns (pack | None, info).

    python -m app.services.joern.vocab.validate                 # validate every shipped pack
    python -m app.services.joern.vocab.validate path/to/x.json  # validate one file
    python -m app.services.joern.vocab.validate --freeze        # rewrite packs/digests.json
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
SCHEMA_FILE = HERE / "schema.json"
PACKS = HERE / "packs"
DIGESTS = PACKS / "digests.json"
BASE_ID = "_base"

_ID_RE = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,39}$")
_AUTHORED = {"hand_written", "framework_docs", "testbed_source"}


def schema() -> dict:
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


_SCHEMA: Optional[dict] = None


def _s() -> dict:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = schema()
    return _SCHEMA


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #

def validate_values(sink: str, values, where: str) -> list[str]:
    """Character class, length, case and cap for one slot's values under one sink."""
    errs: list[str] = []
    sk = _s()["sinks"].get(sink)
    if sk is None:
        return [f"{where}: unknown sink '{sink}'"]
    if not isinstance(values, list):
        return [f"{where}: values must be a list"]
    cap = _s()["limits"]["max_values_per_slot"]
    if len(values) > cap:
        errs.append(f"{where}: {len(values)} values exceeds cap {cap}")
    pat = re.compile(sk["pattern"])
    forbidden = sk.get("forbidden_chars", "")
    for v in values:
        if not isinstance(v, str):
            errs.append(f"{where}: non-string value {v!r}")
            continue
        if len(v) < sk["min_len"]:
            errs.append(f"{where}: '{v}' shorter than {sk['min_len']}")
        if any(ch in v for ch in forbidden):
            errs.append(f"{where}: '{v}' contains a forbidden character ({forbidden!r})")
        if sk["case"] == "lower" and v != v.lower():
            errs.append(f"{where}: '{v}' must be lower-case (matched against lower-cased text)")
        if sk["case"] == "upper" and v != v.upper():
            errs.append(f"{where}: '{v}' must be upper-case (matched against upper-cased code)")
        if not pat.match(v):
            errs.append(f"{where}: '{v}' does not match {sink} class {sk['pattern']}")
    return errs


def validate_structure(pack: dict, where: str = "pack") -> list[str]:
    """Shape + per-slot rules for ONE pack file (before composition). Slots may be a subset here;
    completeness is checked on the effective pack by validate_effective()."""
    errs: list[str] = []
    if not isinstance(pack, dict):
        return [f"{where}: top level must be an object"]
    pid = pack.get("pack_id")
    if not isinstance(pid, str) or not _ID_RE.match(pid):
        errs.append(f"{where}: pack_id missing or not [a-z0-9_.-]")
    if pack.get("schema_version") != _s()["schema_version"]:
        errs.append(f"{where}: schema_version must be {_s()['schema_version']}")
    if pack.get("authored_from") not in _AUTHORED:
        errs.append(f"{where}: authored_from must be one of {sorted(_AUTHORED)}")
    ext = pack.get("extends")
    if ext is not None and (not isinstance(ext, str) or not _ID_RE.match(ext)):
        errs.append(f"{where}: extends must be a pack id")
    allowed = {"pack_id", "schema_version", "authored_from", "extends", "slots",
               "description", "transcript", "sources", "version"}
    for k in pack:
        if k not in allowed:
            errs.append(f"{where}: unknown top-level key '{k}'")
    slots = pack.get("slots")
    if not isinstance(slots, dict):
        return errs + [f"{where}: slots must be an object"]
    known = _s()["slots"]
    for name, body in slots.items():
        w = f"{where}.slots.{name}"
        if name not in known:
            errs.append(f"{w}: unknown slot")
            continue
        if not isinstance(body, dict) or set(body) - {"sink", "values", "note"}:
            errs.append(f"{w}: must be {{sink, values[, note]}}")
            continue
        if body.get("sink") != known[name]["sink"]:
            errs.append(f"{w}: sink must be '{known[name]['sink']}' (declared '{body.get('sink')}')")
            continue
        errs += validate_values(body["sink"], body.get("values"), w)
    return errs


def validate_effective(eff: dict, where: str = "effective") -> list[str]:
    """Completeness + cross-slot rules on the COMPOSED pack (what the Scala will read)."""
    errs: list[str] = []
    slots = eff.get("slots", {})
    for name in _s()["slots"]:
        if name not in slots:
            errs.append(f"{where}: slot '{name}' missing after composition")
    if errs:
        return errs
    vals = lambda n: slots[n]["values"]
    for a in vals("authz_guard"):
        for n in vals("authn_only"):
            if a in n:
                errs.append(f"{where}: authz_guard '{a}' is a substring of authn_only '{n}' "
                            f"(an authn-only construct would satisfy the authz guard)")
    both = set(vals("qty_terms")) & set(vals("price_terms"))
    if both:
        errs.append(f"{where}: qty_terms and price_terms overlap: {sorted(both)}")
    for name, body in slots.items():
        errs += validate_values(body["sink"], body["values"], f"{where}.slots.{name}")
    return errs


# --------------------------------------------------------------------------- #
# composition + hashing
# --------------------------------------------------------------------------- #

def canonical(eff: dict) -> bytes:
    """Deterministic bytes: sorted keys, no whitespace, values sorted + de-duplicated."""
    slots = {n: {"sink": b["sink"], "values": sorted(set(b["values"]))}
             for n, b in eff["slots"].items()}
    doc = {"pack_id": eff["pack_id"], "schema_version": eff["schema_version"],
           "authored_from": eff.get("authored_from"), "extends": eff.get("extends"),
           "chain": eff.get("chain", [eff["pack_id"]]), "slots": slots}
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256(eff: dict) -> str:
    return hashlib.sha256(canonical(eff)).hexdigest()


def compose(child: dict, parent: Optional[dict]) -> dict:
    """child over parent: union per slot; child may only ADD values."""
    slots: dict = {}
    if parent:
        for n, b in parent["slots"].items():
            slots[n] = {"sink": b["sink"], "values": sorted(set(b["values"]))}
    for n, b in child["slots"].items():
        have = set(slots.get(n, {}).get("values", []))
        slots[n] = {"sink": b["sink"], "values": sorted(have | set(b["values"]))}
    chain = (parent.get("chain", [parent["pack_id"]]) if parent else []) + [child["pack_id"]]
    return {"pack_id": child["pack_id"], "schema_version": child["schema_version"],
            "authored_from": child.get("authored_from"), "extends": child.get("extends"),
            "transcript": child.get("transcript"), "chain": chain, "slots": slots}


# --------------------------------------------------------------------------- #
# files
# --------------------------------------------------------------------------- #

def pack_path(pack_id: str) -> Path:
    return PACKS / f"{pack_id}.json"


def shipped() -> list[str]:
    """Pack ids under packs/: every *.json except the digest allowlist and the authoring
    transcripts (<id>.transcript.json), which sit next to their packs."""
    return sorted(p.stem for p in PACKS.glob("*.json")
                  if p.name != DIGESTS.name and not p.name.endswith(".transcript.json"))


def read_file(path: Path) -> tuple[Optional[dict], list[str]]:
    """Size cap BEFORE parse (a 100 MB file must not be json.loads'd), then parse."""
    try:
        size = path.stat().st_size
    except OSError as e:
        return None, [f"{path.name}: {e}"]
    cap = _s()["limits"]["max_pack_bytes"]
    if size > cap:
        return None, [f"{path.name}: {size} bytes exceeds cap {cap}"]
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except (OSError, ValueError) as e:
        return None, [f"{path.name}: {type(e).__name__}: {e}"]


def digests() -> dict:
    try:
        return json.loads(DIGESTS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def build(path: Path, _depth: int = 0) -> tuple[Optional[dict], list[str]]:
    """Read + validate one file, resolve its parent chain from packs/, compose, validate the
    result. Returns (effective, errors); effective is None on any error."""
    raw, errs = read_file(path)
    if errs:
        return None, errs
    errs = validate_structure(raw, path.stem)
    if errs:
        return None, errs
    parent = None
    if raw.get("extends"):
        if _depth + 1 >= _s()["limits"]["max_extends_depth"]:
            return None, [f"{path.stem}: extends chain deeper than {_s()['limits']['max_extends_depth']}"]
        pp = pack_path(raw["extends"])
        if not pp.is_file():
            return None, [f"{path.stem}: parent '{raw['extends']}' not found in packs/"]
        parent, perrs = build(pp, _depth + 1)
        if perrs:
            return None, [f"{path.stem}: parent {raw['extends']} invalid"] + perrs
    eff = compose(raw, parent)
    errs = validate_effective(eff, path.stem)
    if errs:
        return None, errs
    return eff, []


def load(pack: str, allow_unlisted: bool = False) -> tuple[Optional[dict], dict]:
    """Resolve `pack` (a shipped id, or a path to a .json file), build it, check the allowlist.
    Returns (effective | None, info). info always has: requested, id, sha256, source, errors,
    listed. Never raises."""
    info: dict = {"requested": pack, "id": None, "sha256": None, "source": None,
                  "listed": False, "errors": []}
    p = Path(pack)
    if p.suffix == ".json" and p.is_file():
        info["source"] = "file"
    else:
        p = pack_path(pack)
        info["source"] = "shipped"
        if not p.is_file():
            info["errors"] = [f"pack '{pack}' not found"]
            return None, info
    eff, errs = build(p)
    if errs:
        info["errors"] = errs
        return None, info
    info["id"] = eff["pack_id"]
    info["sha256"] = sha256(eff)
    info["listed"] = digests().get(eff["pack_id"]) == info["sha256"]
    if not info["listed"] and not allow_unlisted:
        info["errors"] = [f"pack '{eff['pack_id']}' digest {info['sha256'][:12]} is not in "
                          f"packs/digests.json (run validate --freeze, or allow unlisted)"]
        return None, info
    return eff, info


def freeze() -> dict:
    """Rewrite packs/digests.json from the shipped packs. Refuses if any is invalid."""
    out, bad = {}, {}
    for pid in shipped():
        eff, errs = build(pack_path(pid))
        if errs:
            bad[pid] = errs
        else:
            out[pid] = sha256(eff)
    if bad:
        raise SystemExit("cannot freeze, invalid packs:\n" +
                         "\n".join(f"  {k}: {v[0]}" for k, v in bad.items()))
    DIGESTS.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


# --------------------------------------------------------------------------- #
# pack resolution for a target
# --------------------------------------------------------------------------- #

_SKIP_DIRS = {".venv", "venv", ".git", "node_modules", "__pycache__", "dist", "build", ".tox"}
_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
# framework -> pack id. Order matters: the first framework seen in the evidence wins, and Django
# projects routinely also import flask-free helpers, so django is checked first.
_FRAMEWORKS = [("django", "django"), ("flask", "flask-sqlite3")]


def detect_framework(target: str, max_files: int = 400) -> tuple[Optional[str], str]:
    """(pack id | None, evidence). Reads requirements.txt / pyproject.toml / Pipfile first, then
    the import lines of up to max_files .py files. Only the shipped packs are candidates; a
    framework with no shipped pack resolves to None (-> _base) and says so."""
    root = Path(target)
    if root.is_file():
        root = root.parent
    text = ""
    for name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.cfg", "setup.py"):
        f = root / name
        if f.is_file():
            try:
                text += f.read_text(encoding="utf-8", errors="replace").lower() + "\n"
            except OSError:
                pass
    for fw, pid in _FRAMEWORKS:
        if re.search(rf"(?m)^\s*{fw}\b", text) or f'"{fw}' in text or f"'{fw}" in text:
            return (pid if pack_path(pid).is_file() else None), f"{fw} in project metadata"
    seen = 0
    hits: dict[str, int] = {}
    for py in _iter_py(root):
        seen += 1
        if seen > max_files:
            break
        try:
            src = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _IMPORT_RE.finditer(src):
            mod = m.group(1).lower()
            for fw, _ in _FRAMEWORKS:
                if mod == fw:
                    hits[fw] = hits.get(fw, 0) + 1
    for fw, pid in _FRAMEWORKS:
        if hits.get(fw):
            return (pid if pack_path(pid).is_file() else None), f"{fw} imported in {hits[fw]} file(s)"
    return None, "no known framework imported"


def _iter_py(root: Path):
    import os
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in _SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                yield Path(d) / f


def resolve(target: str, requested: str = "auto") -> tuple[str, str]:
    """(pack id or path to load, reason). `requested` is JOERN_PACK / --pack: 'auto' detects
    from the target; anything else is used as given."""
    if requested and requested.lower() != "auto":
        return requested, "requested"
    pid, why = detect_framework(target)
    if pid is None:
        return BASE_ID, why
    return pid, why


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    if "--freeze" in argv:
        out = freeze()
        for k, v in out.items():
            print(f"  {k:<16} {v}")
        print(f"[vocab] froze {len(out)} pack digest(s) into {DIGESTS.name}")
        return 0
    targets = [a for a in argv if not a.startswith("--")] or shipped()
    rc = 0
    for t in targets:
        eff, info = load(t, allow_unlisted=True)
        if eff is None:
            rc = 1
            print(f"[vocab] {t}: INVALID")
            for e in info["errors"]:
                print(f"    - {e}")
            continue
        n = sum(len(b["values"]) for b in eff["slots"].values())
        print(f"[vocab] {eff['pack_id']:<16} ok  sha256={info['sha256'][:12]}  "
              f"chain={'>'.join(eff['chain'])}  values={n}  "
              f"{'listed' if info['listed'] else 'UNLISTED (run --freeze)'}")
        if not info["listed"]:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
