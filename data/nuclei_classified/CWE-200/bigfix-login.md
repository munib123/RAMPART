# Vulnerability: HCL BigFix Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bigfix-login.yaml`)

## Description
HCL BigFix login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

