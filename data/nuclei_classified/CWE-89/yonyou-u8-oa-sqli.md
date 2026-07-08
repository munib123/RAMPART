# Vulnerability: Yonyou U8 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-oa-sqli.yaml`)

## Description
Yonyou U8 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20md5({{num}}))
```

