# Nuclei Template: ASUS RT-N16 - Default Login
**Template ID:** asus-rtn16-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`asus-rtn16-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ASUS RT-N16 contains a default login vulnerability. Default admin login password 'admin' was found.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

