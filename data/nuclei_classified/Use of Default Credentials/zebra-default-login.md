# Nuclei Template: Zebra - Default Login
**Template ID:** zebra-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`zebra-printer-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Zebra default login credentials was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /authorize HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

0={{username}}&1={{password}}
```

