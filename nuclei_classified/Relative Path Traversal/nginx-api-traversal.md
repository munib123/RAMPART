# Nuclei Template: Nginx Plus Rest API - Traversal
**Template ID:** nginx-api-traversal
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`nginx-api-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Access to Nginx Plus Rest API was discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

## References
- https://nginx.org/en/docs/http/ngx_http_api_module.html
- https://x.com/akshaysharma71/status/1825815869953552844
