# Vulnerability: Cloudlog Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`cloudlog-panel.yaml`)

## Description
Cloudlog panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/index.php/user/login
```

