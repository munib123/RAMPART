# Nuclei Template: 3ware Controller 3DM2 - Default Login
**Template ID:** 3ware-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`3ware-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The default password for logging in to the 3DM2 web interface of a 3ware controller is "3ware" for both the Administrator and User accounts.

## Steps to reproduce / Exploit Payload
```http
POST /login.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

whopwd={{username}}&thepwd={{password}}
```

## References
- https://www.thomas-krenn.com/en/wiki/3ware_Controller_3DM2_Password
