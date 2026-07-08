# Vulnerability: Nginx UI Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nginx-ui-dashboard.yaml`)

## Description
Nginx UI panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

