# Vulnerability: Ecology OA CheckServer - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`weaver-checkserver-sqli.yaml`)

## Description
Ecology OA system improperly filters incoming data from users, resulting in a SQL injection vulnerability. Remote and unauthenticated attackers can use this vulnerability to conduct SQL injection attacks and steal sensitive database information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mobile/plugin/CheckServer.jsp?type=mobileSetting
```

