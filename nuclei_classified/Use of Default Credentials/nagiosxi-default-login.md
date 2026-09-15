# Nuclei Template: Nagios XI Default Admin Login - Detect
**Template ID:** nagiosxi-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**CWE:** CWE-1391
**Source:** Nuclei Template (`nagiosxi-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Nagios XI default admin login credentials were detected.

## Steps to reproduce / Exploit Payload
```http
GET /nagiosxi/login.php HTTP/1.1
Host: {{Hostname}}

POST /nagiosxi/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

nsp={{nsp}}&page=auth&debug=&pageopt=login&username={{username}}&password={{password}}&loginButton=

GET /nagiosxi/index.php HTTP/1.1
Host: {{Hostname}}
```

## References
- https://nagiosxi.demos.nagios.com/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
