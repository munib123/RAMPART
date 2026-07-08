# Vulnerability: n8n Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`n8n-panel.yaml`)

## Description
The worlds most popular workflow automation platform for technical teams

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/signin
```

