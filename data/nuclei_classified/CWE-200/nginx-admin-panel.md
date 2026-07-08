# Vulnerability: Nginx Admin Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nginx-admin-panel.yaml`)

## Description
Nginx Admin Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

