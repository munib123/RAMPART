# RAMPART

A desktop-style **security scanner** that scans code, **grounds** every finding in real
disclosed vulnerabilities (a RAG knowledge base), asks an **LLM to verify** it against
retrieved real-world exemplars, and produces a calm, ranked report. This repository is the
proof-of-concept slice of the full RAMPART pipeline.

```
scan (bandit / semgrep)  ->  extract code slice  ->  RAG ground (ChromaDB)  ->  Gemini verify  ->  ranked report
```

## Layout

```
rampart/
├── backend/                 FastAPI API (Python 3.13, venv-isolated)
│   ├── app/
│   │   ├── main.py          FastAPI app + CORS
│   │   ├── config.py        env / secrets-driven config (.env) + path resolution
│   │   ├── db.py            asyncpg pool (+ graceful no-DB degrade)
│   │   ├── core/            JWT + bcrypt, FastAPI auth deps
│   │   ├── routers/         auth, scans, scan, fix, browse, health
│   │   ├── schemas/         Pydantic request models
│   │   └── services/        scanner, extract, rag, gemini, pipeline
│   ├── db/schema.sql        Supabase/Postgres schema (users, scans, findings, cwe_stats)
│   ├── tests/               lightweight smoke/health checks
│   ├── requirements.txt     pinned Python deps
│   ├── run_server.py        start API only
│   └── .venv/               virtual environment (git-ignored)
├── frontend/                Vite + React + TS SPA (and Tauri shell)
│   ├── src/                 App, pages, components, hooks, api, contexts, styles
│   └── src-tauri/           optional Rust/Tauri desktop shell
├── knowledge_base/          RAG source (builds the Chroma store; README inside)
├── semgrep_test/            bundled vulnerable sample code
├── data/                    raw sources (nuclei_classified/, etc.)
├── .env / .env.example      secrets config (git-ignored)
└── README.md
```

The knowledge base (`knowledge_base/`) and the bundled vulnerable sample
(`semgrep_test/`) live **inside this repo**, alongside `backend/` `frontend/` and `data/`.
Path configuration in `backend/app/config.py` resolves everything relative to this repo
root, so it works regardless of where the directory is moved.

---

## Quick start

### One-command (both processes) — from `frontend/`

```bash
cd frontend
npm run dev:all
```

This concurrently launches:

- **backend** - FastAPI on `http://127.0.0.1:8000/` (API docs at `/docs`)
- **frontend** - Vite dev server on `http://127.0.0.1:5173/`

`Ctrl+C` stops both. Enter a folder/file path, pick a scanner, press **Start scan**. The
default points at the bundled vulnerable sample (`semgrep_test/test_code`).

### Manual / split startup

| What | Command |
|---|---|
| Backend only | `backend\.venv\Scripts\python.exe backend\run_server.py` |
| Frontend only | `cd frontend && npm run dev:web` |
| Frontend + backend together (npm) | `cd frontend && npm run dev:all` |

### Prereqs (already done in this working copy, re-run if cloning fresh)

```bash
python -m venv backend/.venv
backend\.venv\Scripts\pip install -r backend\requirements.txt
cd frontend && npm install
```

---

## Enable the LLM (Gemini) verdict - optional but recommended

1. Copy `.env.example` to `.env` (git-ignored).
2. Paste your **Google AI Studio** Gemini key (`AIzaSy...`) into `GEMINI_API_KEY`. Get one at
   <https://aistudio.google.com/apikey>. **Rotate any key you have shared in chat.**
3. Restart. Findings then carry a grounded verdict (Confirmed / Likely / Informational /
   False positive), a confidence score, a plain-English explanation, and a suggested fix.

Without a key the app still runs: you get findings and the retrieved real-world exemplars;
only the LLM verdict is marked "Unverified".

**Model / quota:** the default is `gemini-3.5-flash-lite` (settable via `GEMINI_MODEL`). Free-tier
limits are **per-day, per-model**. All findings are verified in **one batched call per scan**
(`gemini.analyze_batch`), so a scan costs ~1 request. Rotate models or enable billing to lift the
daily cap.

---

## Semgrep (multi-language) - runs natively from the venv

Bandit works out of the box but is **Python-only**. Semgrep covers many languages and is already
installed in the project venv (`semgrep==1.172.0` in `requirements.txt`, launched through the
venv's Python), so no extra setup is needed. The app uses `DEFAULT_SCANNER = "auto"`: it prefers
semgrep (multi-language) when it runs, and falls back to Bandit (python-only) otherwise.

If you ever need to (re)install it in the venv:

```bash
backend\.venv\Scripts\python -m pip install semgrep
```

> Note: the code keeps a thin WSL path-translation (`/mnt/d/...` <-> `D:\...`) for forward
> compatibility, but on this box semgrep runs **natively from `backend\.venv`**, not WSL.

---

## What each piece is

| Part | File | Notes |
|---|---|---|
| Scanner (pluggable) | `backend/app/services/scanner.py` | `auto` = semgrep (multi-language, native venv) when runnable, else bandit (python). Same normalized `Finding` shape either way. |
| Code-slice extract | `backend/app/services/extract.py` | containing function (Python AST) or a line window |
| RAG | `backend/app/services/rag.py` | queries `rampart_hackerone_minilm` + `rampart_nuclei_minilm` Chroma collections, CWE-filtered |
| LLM verify | `backend/app/services/gemini.py` | Gemini, grounded in exemplars; key from `.env` only. Batch API for ~1 request per scan |
| Suggest a fix | `generate_fix` in `gemini.py` + `POST /api/fix` | on-demand corrected code per finding; UI shows a diff + Copy (no auto-apply) |
| Orchestration | `backend/app/services/pipeline.py` | scan -> extract -> ground -> verify -> rank |
| API | `backend/app/main.py` | FastAPI on localhost; CORS for the dev/Tauri webviews |
| Database | `backend/db/schema.sql`, `app/db.py` | optional Supabase/Postgres via `DATABASE_URL`; degrades gracefully when unset |
| Auth | `app/routers/auth.py`, `app/core/security.py` | bcrypt + JWT (email/password) |
| UI | `frontend/src` | React SPA; **Tauri-ready** (the shell loads this frontend and runs the backend as a sidecar) |

### API endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scan` | run a full scan; persists when signed in |
| GET | `/api/health` | scanner/LLM/RAG/db availability |
| POST | `/api/fix` | generate a fix for one finding |
| GET | `/api/browse` | native folder picker |
| POST | `/api/auth/signup`, `/api/auth/login` | register / log in |
| GET | `/api/auth/me` | who am I (Bearer) |
| GET / POST | `/api/scans` | list / save scans |
| GET | `/api/scans/{id}` | one saved scan |
| GET | `/api/research/overview` | CWE aggregate stats |

---

## Notes / current limits (honest)

- **Semgrep** runs **natively from the project virtual environment** (`backend\.venv`);
  `auto` prefers it (multi-language) and falls back to Bandit (python-only) when not installed.
- Embeddings use the **MiniLM placeholder** index (torch/gte-large can't build on this box);
  retrieval quality improves once a gte-large index is built on a GPU.
- Persistence is optional: without `DATABASE_URL` the app runs fully, only scan history / auth are
  disabled.
- LLM quota: free-tier limits are per-day per-model; a scan costs ~1 batched call to stay within budget.
- Later (per the design): more knowledge-base sources and the self-verifying remediation loop.

---

*Verification: `npm run build` (tsc + vite) passes; backend smoke tests live under `backend/tests/`.*