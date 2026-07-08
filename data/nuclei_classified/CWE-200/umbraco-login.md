# Vulnerability: Umbraco Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`umbraco-login.yaml`)

## Description
Umbraco login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/umbraco
GET {{BaseURL}}/umbraco/login
```

