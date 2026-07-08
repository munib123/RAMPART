# Vulnerability: Teleport Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`teleport-login-panel.yaml`)

## Description
Detects Teleport web login interface exposed at /web/login and version information from /webapi/ping

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webapi/ping
```

