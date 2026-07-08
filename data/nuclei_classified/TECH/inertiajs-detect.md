# Vulnerability: Inertia.js - Detect
**Classification:** TECH
**Source:** Nuclei Template (`inertiajs-detect.yaml`)

## Description
Detected Inertia.js passively using a single plain GET request with no special headers. It matched four server-emitted Inertia-specific signals on the initial document: three proximity-bound body patterns covering the embedded page object formats and one `Vary: X-Inertia` response header signal set by supported middleware adapters.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

