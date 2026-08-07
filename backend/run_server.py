"""Start the RAMPART backend (API only). Run: .venv\\Scripts\\python.exe run_server.py

This only starts FastAPI on 127.0.0.1:8000. It does NOT serve any UI - the
frontend is a separate process (see frontend/: `npm run dev` / `npm run tauri dev`).
"""
import os
import sys

import uvicorn

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

from app.main import app  # noqa: E402

if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 8000
    print(f"RAMPART API starting on http://{HOST}:{PORT}/  (docs at /docs, Ctrl+C to stop)")
    print("Loading scanners / RAG embedder / Gemini - first boot can take 10-30s without output, please wait...")
    # log_level=info so uvicorn prints its "running on" + "Application startup complete"
    # lines - with 'warning' it shows nothing and looks like it is stuck.
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")