# Vulnerability: Nginx Vhost Traffic Status
**Classification:** STATUS
**Source:** Nuclei Template (`nginx-vhost-traffic-status.yaml`)

## Description
Nginx Vhost Traffic status is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status
```

