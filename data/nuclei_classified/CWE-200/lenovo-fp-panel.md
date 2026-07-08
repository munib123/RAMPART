# Vulnerability: Lenovo Fan Power Controller Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lenovo-fp-panel.yaml`)

## Description
Lenovo Fan Power Controller login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login.html
```

