# Nuclei Template: XdCMS - SQL Injection
**Template ID:** xdcms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`xdcms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
XdCMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/index.php?m=member&f=login_save
```

## References
- https://www.uedbox.com/post/35188/
