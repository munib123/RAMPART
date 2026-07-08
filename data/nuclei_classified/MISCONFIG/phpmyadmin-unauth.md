# Vulnerability: PhpMyAdmin - Unauthenticated Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`phpmyadmin-unauth.yaml`)

## Description
Unauthenticated Access to phpmyadmin dashboard.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{path}} HTTP/1.1
Host: {{Hostname}}
```

