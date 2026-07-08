# Vulnerability: Replit User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`replit.yaml`)

## Description
Replit user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://replit.com/@{{user}}
```

