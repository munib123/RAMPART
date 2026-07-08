# Vulnerability: Content Central Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`content-central-login.yaml`)

## Description
Content Central login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.aspx
GET {{BaseURL}}/ContentCentral/login.aspx/
```

