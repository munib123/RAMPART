# Vulnerability: Bigant DataBase - Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`bigant-db-install.yaml`)

## Description
Bigant DataBase Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /install/update.html  HTTP/1.1
Host: {{Hostname}}
```

