// RAMPART Tauri shell - spawns the FastAPI backend as a localhost sidecar so the
// packaged desktop app is fully self-contained (frontend webview + local API).
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::Manager;

struct BackendState(Mutex<Option<Child>>);

/// Resolve the command that starts the RAMPART backend.
///
/// Resolution order:
///   1. `RAMPART_BACKEND_CMD` env var - explicit override (e.g. an absolute path to a
///      frozen backend binary/script).
///   2. Dev default: `<repo>\backend\.venv\Scripts\python.exe <repo>\backend\run_server.py`
///      (found by walking up from the crate dir).
///   3. Packaged fallback: `resources/run_server.py` if bundled alongside the app.
fn resolve_backend() -> Result<(PathBuf, Vec<String>), String> {
    // 1. explicit override
    if let Ok(cmd) = std::env::var("RAMPART_BACKEND_CMD") {
        let mut parts = cmd.split_whitespace();
        let exe = parts.next().ok_or("RAMPART_BACKEND_CMD is empty")?;
        let args: Vec<String> = parts.map(str::to_string).collect();
        return Ok((exe.into(), args));
    }

    // 2. locate the repo backend when the crate is built in place
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // frontend/src-tauri
    let mut probe = crate_dir.clone();
    probe.push("..");
    probe.push("..");
    let repo = probe; // frontend/src-tauri/../.. -> <repo root>
    for path in [repo.join("backend").join(".venv"), repo.join("backend").join("venv")] {
        let py = path.join("Scripts").join("python.exe");
        let script = repo.join("backend").join("run_server.py");
        if py.is_file() && script.is_file() {
            return Ok((py, vec![script.to_string_lossy().to_string()]));
        }
    }

    // 3. packaged resources
    let res = crate_dir.join("../resources").join("backend").join("run_server.py");
    if res.is_file() {
        return Ok(("python".into(), vec![res.to_string_lossy().to_string()]));
    }

    Err("No backend found. Set RAMPART_BACKEND_CMD or run from the repo with backend/.venv built.".into())
}

fn start_backend(app: &tauri::App) -> Result<(), String> {
    let (exe, args) = resolve_backend()?;
    let ready = app.try_state::<BackendState>();
    if let Some(state) = ready {
        if state.0.lock().unwrap().is_some() {
            return Ok(()); // already running
        }
    }
    let child = Command::new(&exe)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn backend `{}`: {e}", exe.display()))?;

    app.manage(BackendState(Mutex::new(Some(child))));
    println!("RAMPART backend started ({} {})", exe.display(), args.join(" "));
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if let Err(e) = start_backend(app) {
                eprintln!("RAMPART backend could not be started: {e}");
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // give the API a moment to finish any in-flight request then exit
                let app = window.app_handle();
                if let Some(state) = app.try_state::<BackendState>() {
                    if let Some(mut child) = state.0.lock().unwrap().take() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running RAMPART");
}