# Vulnerability: Checkpoint Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`checkpoint-panel.yaml`)

## Description
Checkpoint login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sslvpn/Login/Login
GET {{BaseURL}}/Login/Login
```

