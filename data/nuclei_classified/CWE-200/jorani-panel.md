# Vulnerability: Jorani Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jorani-panel.yaml`)

## Description
Jorani login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/index.php/session/login
```

