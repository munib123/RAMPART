# Vulnerability: One Identity Password Manager Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`oipm-detect.yaml`)

## Description
One Identity Password Manager is a secure password manager that gives enterprises control over password management, policies, and automated reset functions.

## Secure Mitigation
Ensure proper access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/PMUser/
```

