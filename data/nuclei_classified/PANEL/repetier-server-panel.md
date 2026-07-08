# Vulnerability: Repetier Server Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`repetier-server-panel.yaml`)

## Description
Repetier Server login panel detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#!/login
```

