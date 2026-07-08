# Vulnerability: Joplin Server Login - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`joplin-panel.yaml`)

## Description
Joplin Server login panel detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

