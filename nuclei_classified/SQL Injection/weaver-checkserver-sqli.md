# Nuclei Template: Ecology OA CheckServer - SQL Injection
**Template ID:** weaver-checkserver-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`weaver-checkserver-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Ecology OA system improperly filters incoming data from users, resulting in a SQL injection vulnerability. Remote and unauthenticated attackers can use this vulnerability to conduct SQL injection attacks and steal sensitive database information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mobile/plugin/CheckServer.jsp?type=mobileSetting
```

## References
- https://stack.chaitin.com/techblog/detail?id=81
- https://github.com/lal0ne/vulnerability/blob/main/%E6%B3%9B%E5%BE%AE/E-Cology/CheckServer/README.md
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/weaver-ecology-oa-plugin-checkserver-setting-sqli.yaml
