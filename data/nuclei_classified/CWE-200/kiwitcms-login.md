# Vulnerability: Kiwi TCMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kiwitcms-login.yaml`)

## Description
Kiwi TCMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/accounts/login/
```

