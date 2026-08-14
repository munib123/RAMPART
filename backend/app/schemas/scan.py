"""Request/response models for scan + fix endpoints (moved verbatim from the old
top-level app.py: ScanReq, FixReq)."""
from __future__ import annotations

from pydantic import BaseModel


class ScanReq(BaseModel):
    path: str | None = None
    scanner: str | None = None
    scope: dict | None = None


class FixReq(BaseModel):
    code: str
    cwe_id: str | None = ""
    title: str | None = ""
    message: str | None = ""
    exemplars: list | None = None
    scan_id: str | None = None


class ApplyFixReq(BaseModel):
    scan_id: str
    path: str                 # absolute path of the file to edit
    start_line: int
    end_line: int
    fixed_code: str           # from the already-generated fix
    original_code: str | None = None   # slice.code from the report; powers the content guard


class RevertReq(BaseModel):
    scan_id: str
    target: str               # the scanned root (folder or file)