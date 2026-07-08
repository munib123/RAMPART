# Vulnerability: SmartPing Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`smartping-dashboard.yaml`)

## Description
SmartPing Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.html
```

