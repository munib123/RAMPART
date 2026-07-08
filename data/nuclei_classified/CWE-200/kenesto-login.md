# Vulnerability: Kenesto - Login Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kenesto-login.yaml`)

## Description
Kenesto login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Kenesto/Account/LogOn?ReturnUrl=%2fkenesto
```

