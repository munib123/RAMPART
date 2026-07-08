# Vulnerability: temBoard Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`temboard-panel.yaml`)

## Description
temBoard was detected — a powerful management tool for PostgreSQL.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

