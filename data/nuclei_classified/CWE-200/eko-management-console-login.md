# Vulnerability: Eko Charger Management Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`eko-management-console-login.yaml`)

## Description
Eko Charger Management Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

