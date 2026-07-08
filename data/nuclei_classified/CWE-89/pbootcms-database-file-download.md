# Vulnerability: PbootCMS 2.0.7 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`pbootcms-database-file-download.yaml`)

## Description
PbootCMS 2.0.7 contains a SQL injection vulnerability via pbootcms.db.  An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/data/pbootcms.db
```

