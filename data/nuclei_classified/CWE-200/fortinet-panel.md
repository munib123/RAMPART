# Vulnerability: Fortinet Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortinet-panel.yaml`)

## Description
Fortinet login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

