# Vulnerability: SQL Buddy Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sqlbuddy-panel.yaml`)

## Description
SQL Buddy login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/sqlbuddy/
```

