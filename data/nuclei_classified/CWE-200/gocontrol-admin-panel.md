# Vulnerability: Go.Control Event Administration Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gocontrol-admin-panel.yaml`)

## Description
Detects the presence of the Go.Control Event Administration login panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/
GET {{BaseURL}}/admin/index.php
```

