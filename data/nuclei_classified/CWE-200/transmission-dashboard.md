# Vulnerability: Transmission Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`transmission-dashboard.yaml`)

## Description
Transmission dashboard was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/transmission/web/
```

