# Nuclei Template: Kettle - Default Login
**Template ID:** kettle-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`kettle-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Kettle contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

