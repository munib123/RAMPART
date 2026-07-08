# Vulnerability: Phabricator Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phabricator-login.yaml`)

## Description
Phabricator login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login/
```

