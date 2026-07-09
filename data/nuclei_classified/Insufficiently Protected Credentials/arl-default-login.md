# Nuclei Template: ARL Default Admin Login
**Template ID:** arl-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`arl-default-login.yaml`)

## Vulnerability Information & PoC

## Description
An ARL default admin login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json; charset=UTF-8

{"username":"{{username}}","password":"{{password}}"}
```

