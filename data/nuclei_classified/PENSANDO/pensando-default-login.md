# Vulnerability: AMD Pensando PSM - Default Login
**Classification:** PENSANDO
**Source:** Nuclei Template (`pensando-default-login.yaml`)

## Description
The AMD Pensando Policy and Services Manager used a default password for the admin account.This allowed instances to be accessed using the default credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
POST /v1/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","tenant":"default"}
```

