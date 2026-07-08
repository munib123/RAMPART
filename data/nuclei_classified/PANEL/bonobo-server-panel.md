# Vulnerability: Bonobo Git Server Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`bonobo-server-panel.yaml`)

## Description
Bonobo Git Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/git
```

