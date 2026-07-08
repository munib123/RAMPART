# Vulnerability: Residential Gateway Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`residential-gateway-login.yaml`)

## Description
Residential Gateway login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/cgi-bin/wwwctrl.cgi?action=home
```

