# Vulnerability: Saltbo/zpan Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`saltbo-zpan-panel.yaml`)

## Description
Detects the presence of the Saltbo/zpan file management panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

