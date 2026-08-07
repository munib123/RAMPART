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
COLLECTIONS = ["rampart_hackerone_minilm", "rampart_nuclei_minilm"]
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

# --- Supabase / Postgres ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_PUBLISHABLE_KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# --- Auth (JWT) ---
JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MIN = int(os.environ.get("JWT_EXPIRE_MIN", "30").strip() or 30)
