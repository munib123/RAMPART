# Vulnerability: Jenkins Login Detected
**Classification:** CWE-200
**Source:** Nuclei Template (`jenkins-login.yaml`)

## Description
Jenkins is an open source automation server.

## Secure Mitigation
Ensure proper access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

