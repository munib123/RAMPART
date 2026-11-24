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
# Free-tier daily quotas are PER MODEL. When GEMINI_MODEL's daily quota is exhausted the process
# fails over to the next model here, in order, for the rest of its life (logged, shown in
# /api/health as "model"). Comma-separated; empty = no failover.
GEMINI_FALLBACK_MODELS = [m.strip() for m in os.environ.get("GEMINI_FALLBACK_MODELS", "").split(",") if m.strip()]

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
# Resource bounds for the scanner subprocesses (S5). Env-overridable; no detection change.
SEMGREP_JOBS = max(1, int(os.environ.get("SEMGREP_JOBS", str(max(1, min(4, os.cpu_count() or 1)))).strip() or 1))
SEMGREP_RULE_TIMEOUT = max(1, int(os.environ.get("SEMGREP_RULE_TIMEOUT", "30").strip() or 30))
SEMGREP_MAX_TARGET_BYTES = max(1, int(os.environ.get("SEMGREP_MAX_TARGET_BYTES", "1000000").strip() or 1000000))
BANDIT_TIMEOUT = max(1, int(os.environ.get("BANDIT_TIMEOUT", "600").strip() or 600))

# --- Performance: local caches, scan queue, profiling (S3) ---
# Raw scanner + Joern output is cached here, keyed by a tree fingerprint (24 h TTL).
# The directory is git-ignored and safe to delete at any time.
_cache_env = os.environ.get("RAMPART_CACHE_DIR", "").strip()
CACHE_DIR = Path(_cache_env) if _cache_env else (FYP / "backend" / ".cache")
if not CACHE_DIR.is_absolute():
    CACHE_DIR = FYP / CACHE_DIR
SCAN_CACHE = os.environ.get("RAMPART_SCAN_CACHE", "on").strip().lower() not in ("off", "0", "false", "no")
# Chroma and the single Joern sidecar are shared process state, so scans are single-flight by
# default. A queued request waits up to SCAN_QUEUE_TIMEOUT seconds, then gets 429 scan_busy.
SCAN_CONCURRENCY = max(1, int(os.environ.get("RAMPART_SCAN_CONCURRENCY", "1").strip() or 1))
SCAN_QUEUE_TIMEOUT = float(os.environ.get("RAMPART_SCAN_QUEUE_TIMEOUT", "300").strip() or 300)
PROFILE = os.environ.get("RAMPART_PROFILE", "0").strip().lower() in ("1", "true", "yes", "on")

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
# P5: which vocabulary pack the locator rules read. auto = detect the framework from the target
# (django -> django, flask -> flask-sqlite3, else _base); or a shipped pack id / path to a .json.
JOERN_PACK        = os.environ.get("JOERN_PACK", "auto").strip() or "auto"
# an unlisted pack (digest not in vocab/packs/digests.json) loads only when this is set - for
# authoring; the scan diag marks it `unlisted`
JOERN_PACK_ALLOW_UNLISTED = os.environ.get("JOERN_PACK_ALLOW_UNLISTED", "").strip().lower() in ("1", "true", "yes")

# --- Supabase / Postgres ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_PUBLISHABLE_KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# --- Auth (JWT) ---
JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MIN = int(os.environ.get("JWT_EXPIRE_MIN", "30").strip() or 30)
if not JWT_SECRET:
    print("[config] WARNING: JWT_SECRET is not set - sign-in will fail. "
          "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
elif len(JWT_SECRET) < 32:
    print(f"[config] WARNING: JWT_SECRET is only {len(JWT_SECRET)} characters; use at least 32.")

# --- Local API safety (S5) ---
# The UI is a browser dev server (:5173) or the Tauri webview. Only these origins may call the
# local API; set CORS_ORIGINS (comma-separated) for a custom dev port, or RAMPART_CORS_ALL=1 to
# restore the old "*" behaviour. `allow_origins=["*"]` lets any web page trigger local scans.
_DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:4173", "http://127.0.0.1:4173",   # `vite preview`
    "tauri://localhost", "http://tauri.localhost", "https://tauri.localhost",
]
_cors_env = os.environ.get("CORS_ORIGINS", "").strip()
CORS_ORIGINS = (
    [o.strip() for o in _cors_env.split(",") if o.strip()]
    if _cors_env else _DEFAULT_CORS_ORIGINS
)
CORS_ALL = os.environ.get("RAMPART_CORS_ALL", "0").strip().lower() in ("1", "true", "yes", "on")
MAX_BODY_BYTES = max(1024, int(os.environ.get("RAMPART_MAX_BODY_BYTES", "5242880").strip() or 5242880))
REQUIRE_AUTH_SCAN = os.environ.get("RAMPART_REQUIRE_AUTH_SCAN", "0").strip().lower() in ("1", "true", "yes", "on")
AUTH_RATE = os.environ.get("RAMPART_AUTH_RATE", "5/min,30/hour").strip() or "5/min,30/hour"
# Target allow-policy: refuse drive roots and OS/system trees. Explicit opt-in for advanced use.
ALLOW_SYSTEM_TARGETS = os.environ.get("RAMPART_ALLOW_SYSTEM_TARGETS", "0").strip().lower() in ("1", "true", "yes", "on")

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
