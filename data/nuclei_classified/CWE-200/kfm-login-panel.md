# Vulnerability: Kae's File Manager Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kfm-login-panel.yaml`)

## Description
Kae's File Manager admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kfm/admin/
```

