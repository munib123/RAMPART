# Vulnerability: Gitblit Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gitblit-panel.yaml`)

## Description
Gitblit login panel was detected — a pure Java stack for managing, viewing, and serving Git repositories.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

