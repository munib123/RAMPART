# Vulnerability: APC UPS Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apc-ups-login.yaml`)

## Description
APC UPS panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/logon.htm
```

