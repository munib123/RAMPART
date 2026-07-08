# Vulnerability: JFrog Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jfrog-login.yaml`)

## Description
JFrog login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login/
GET {{BaseURL}}/ui/favicon.ico
```

