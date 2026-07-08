# Vulnerability: Hangfire Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hangfire-dashboard.yaml`)

## Description
Hangfire Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/hangfire
```

