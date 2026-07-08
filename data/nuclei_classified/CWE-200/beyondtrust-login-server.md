# Vulnerability: BeyondTrust Privileged Access Management Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`beyondtrust-login-server.yaml`)

## Description
BeyondTrust Privileged Access Management login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/WebConsole/api/security/auth/loginServers
```

