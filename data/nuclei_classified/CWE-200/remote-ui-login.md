# Vulnerability: Canon Remote UI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`remote-ui-login.yaml`)

## Description
Canon Remote UI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

