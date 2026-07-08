# Vulnerability: Selenoid UI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`selenoid-ui-exposure.yaml`)

## Description
Selenoid UI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

