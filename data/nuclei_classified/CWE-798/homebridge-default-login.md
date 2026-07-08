# Vulnerability: Homebridge - Default Admin Credentials
**Classification:** CWE-798
**Source:** Nuclei Template (`homebridge-default-login.yaml`)

## Description
Detected Homebridge UI was found using default administrator credentials (admin:admin). An attacker could have gained full access to manage HomeKit accessories, plugins, and server configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

