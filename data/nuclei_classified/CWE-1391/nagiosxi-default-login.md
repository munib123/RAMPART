# Vulnerability: Nagios XI Default Admin Login - Detect
**Classification:** CWE-1391
**Source:** Nuclei Template (`nagiosxi-default-login.yaml`)

## Description
Nagios XI default admin login credentials were detected.

## Vulnerable Code Pattern / Exploit Payload
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

