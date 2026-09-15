"""POC configuration. Secrets come from the environment / a git-ignored .env - never hardcoded."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent   # G:/FYP/RAMPART/
FYP = ROOT                                             # RAMPART/ holds knowledge_base + semgrep_test siblings

# Load .env if present (git-ignored). python-dotenv is already installed.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:
    pass

# --- LLM (Gemini) ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite").strip()

# --- Knowledge base (the RAG we built) ---
KB_DIR = FYP / "knowledge_base"
CHROMA_DIR = KB_DIR / "out" / "chroma"
COLLECTIONS = ["rampart_hackerone_minilm", "rampart_nuclei_minilm", "rampart_crossvul_minilm"]
RAG_K = 4

# --- LLM verification bounds ---
# All findings are verified in ONE batched call (chunked by LLM_BATCH) so a scan costs ~1 request,
# not one-per-finding - essential under free-tier daily limits.
LLM_BATCH = 12           # findings analysed per Gemini call
MAX_LLM_FINDINGS = 60    # verify at most this many (highest severity first); rest shown unverified

# --- Scanner ---
DEFAULT_SCANNER = "auto"        # semgrep (multi-language) when runnable, else bandit (python)
SEMGREP_CONFIG = "auto"         # semgrep ruleset (auto = fetch registry rules)
DEFAULT_TARGET = str(FYP / "semgrep_test" / "test_code")

# --- Joern / CPG phase (the SAST-blind logic-bug locator; Python targets) ---
# Pure-JVM, runs natively on Windows. The runtime (portable JRE 21 + joern-cli) is installed
# under tools/ by `python -m app.services.joern.runtime --install`; nothing is hard-coded to a
# system Java. All overridable by env var.
JOERN_ENABLED     = os.environ.get("JOERN_ENABLED", "auto").strip()      # auto | on | off
JOERN_HOME        = os.environ.get("JOERN_HOME", "").strip()             # default: tools/joern-cli
JOERN_JAVA_HOME   = os.environ.get("JOERN_JAVA_HOME", "").strip()        # default: tools/jre-21*
JOERN_TIMEOUT     = int(os.environ.get("JOERN_TIMEOUT", "360").strip() or 360)   # s, CPG build + rules
# Reserved verify slots for CPG candidates. pipeline sorts by severity with a STABLE sort and
# appends Joern findings, so without this every CPG candidate on a real repo falls past
# MAX_LLM_FINDINGS into "Unverified" - the phase that exists to find what semgrep cannot would
# be the first thing starved.
JOERN_LLM_QUOTA   = int(os.environ.get("JOERN_LLM_QUOTA", "20").strip() or 20)
# P3: the CPGQL server sidecar. auto|on = start `joern --server` once per backend process and
# send each scan's rule sections as separate /query-sync requests (JVM start paid once; a
# compile error in one rule costs that rule only). off = one `joern --script` per scan.
# Script mode is always the fallback when the server is not ready.
JOERN_SERVER      = os.environ.get("JOERN_SERVER", "auto").strip()          # auto | on | off
JOERN_SERVER_PORT = int(os.environ.get("JOERN_SERVER_PORT", "8091").strip() or 8091)
JOERN_SERVER_WAIT = float(os.environ.get("JOERN_SERVER_WAIT", "0").strip() or 0)   # s a scan waits for a starting server

# --- Supabase / Postgres ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_PUBLISHABLE_KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# --- Auth (JWT) ---
JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MIN = int(os.environ.get("JWT_EXPIRE_MIN", "30").strip() or 30)

# --- Plans / billing (single source of truth) ---
# Quotas are cumulative per-plan totals on the users row (no monthly job). A "fix" charges
# once per distinct scan (see users.last_fix_scan_id), so fixes = how many scans were fixed.
PLANS = {
    "free":    {"label": "Free",    "scans": 10,   "fixes": 5,   "price": 0,        "note": "For trying RAMPART on small projects"},
    "pro":     {"label": "Pro",     "scans": 30,   "fixes": 20,  "price": "$13/mo",  "note": "For serious teams"},
    "premium": {"label": "Premium", "scans": 500,  "fixes": 200, "price": "$30/mo",  "note": "For whole orgs"},
}
# Model routing is UI-advertised per plan but STILL uses the single working GEMINI_MODEL for now.
PLAN_MODEL = {"free": GEMINI_MODEL, "pro": GEMINI_MODEL, "premium": GEMINI_MODEL}
# FUTURE: point pro/premium at heavier models (e.g. gemini-2.5-pro) by editing only this map.

# --- Local fix snapshots (apply/revert safety net) ---
# A whole-target copy taken at the moment of the first Apply for a scan; Revert restores it.
FIX_SNAPSHOT_DIR = FYP / "backend" / ".fix_snapshots"   # git-ignored; <scan_id>/ per scan
