# Vulnerability: Maestro LuCI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`maestro-login-panel.yaml`)

## Description
Maestro LuCI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/luci
```

