"""GET /api/browse - native folder picker (PowerShell dialog) returning the chosen absolute path."""
from __future__ import annotations

import subprocess

from fastapi import APIRouter

router = APIRouter(tags=["browse"])


@router.get("/api/browse")
def browse():
    """Open a native folder picker on the local machine and return the chosen absolute path.
    The dialog is owned by a small on-screen TOPMOST window so it appears in front of the
    browser (a 1x1 form centred on the primary screen keeps it invisible while anchoring
    the dialog on-screen)."""
    ps = r"""
Add-Type -AssemblyName System.Windows.Forms | Out-Null
[System.Windows.Forms.Application]::EnableVisualStyles()
$owner = New-Object System.Windows.Forms.Form
$owner.StartPosition = 'CenterScreen'
$owner.FormBorderStyle = 'None'
$owner.Size = New-Object System.Drawing.Size(1,1)
$owner.ShowInTaskbar = $false
$owner.TopMost = $true
$owner.Show(); $owner.Activate()
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = 'Select a folder to scan'
$d.ShowNewFolderButton = $false
$res = $d.ShowDialog($owner)
$owner.Close(); $owner.Dispose()
if ($res -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write($d.SelectedPath) }
"""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-STA", "-WindowStyle", "Hidden",
             "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=300,
        )
        return {"path": proc.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"path": "", "error": "picker timed out"}
    except Exception as e:
        return {"path": "", "error": f"{type(e).__name__}: {e}"}