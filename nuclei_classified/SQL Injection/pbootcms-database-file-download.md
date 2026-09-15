# Nuclei Template: PbootCMS 2.0.7 - SQL Injection
**Template ID:** pbootcms-database-file-download
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`pbootcms-database-file-download.yaml`)

## Vulnerability Information & PoC

## Description
PbootCMS 2.0.7 contains a SQL injection vulnerability via pbootcms.db.  An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/data/pbootcms.db
```

## References
- https://xz.aliyun.com/t/7628
- https://www.cnblogs.com/0daybug/p/12786036.html
