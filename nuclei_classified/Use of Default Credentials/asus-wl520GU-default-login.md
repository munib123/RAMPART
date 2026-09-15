# Nuclei Template: ASUS WL-520GU - Default Login
**Template ID:** asus-wl520GU-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`asus-wl520GU-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ASUS WL-520GU contains a default login vulnerability. The default admin login password 'admin' was found.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

