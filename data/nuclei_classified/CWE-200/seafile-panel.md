# Vulnerability: Seafile Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`seafile-panel.yaml`)

## Description
Seafile panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/accounts/login/
```

