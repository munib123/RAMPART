# Vulnerability: Nginx Dashboard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauthenticated-nginx-dashboard.yaml`)

## Description
Nginx Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard.html
```

