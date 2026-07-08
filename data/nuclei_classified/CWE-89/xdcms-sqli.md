# Vulnerability: XdCMS - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`xdcms-sqli.yaml`)

## Description
XdCMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/index.php?m=member&f=login_save
```

