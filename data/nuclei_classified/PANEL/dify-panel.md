# Vulnerability: Dify Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`dify-panel.yaml`)

## Description
Dify panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/signin
GET {{BaseURL}}
```

