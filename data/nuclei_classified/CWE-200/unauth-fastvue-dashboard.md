# Vulnerability: Fastvue Dashboard Panel - Unauthenticated Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-fastvue-dashboard.yaml`)

## Description
Fastvue Dashboard panel was detected without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard.aspx
```

