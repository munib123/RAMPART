# Vulnerability: BookStack Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bookstack-panel.yaml`)

## Description
Bookstack login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

