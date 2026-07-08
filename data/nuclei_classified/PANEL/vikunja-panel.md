# Vulnerability: Vikunja Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`vikunja-panel.yaml`)

## Description
Vikunja login panel was detected. Vikunja is a self-hosted to-do and project management application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

