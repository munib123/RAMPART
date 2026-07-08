# Vulnerability: Zuul Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zuul-panel.yaml`)

## Description
ZUUL panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/tenants
GET {{BaseURL}}/api/status
```

