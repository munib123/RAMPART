# Vulnerability: Kasm Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kasm-login-panel.yaml`)

## Description
Kasm workspaces login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /#/login HTTP/1.1
Host: {{Hostname}}

POST /api/login_settings HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"token":null,"username":null}
```

