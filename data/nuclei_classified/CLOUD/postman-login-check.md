# Vulnerability: Postman Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`postman-login-check.yaml`)

## Description
Checks for a valid postman account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://identity.getpostman.com/login HTTP/1.1
Host: identity.getpostman.com
Referer: https://identity.getpostman.com/accounts

POST https://identity.getpostman.com/login HTTP/1.1
Host: identity.getpostman.com
Content-Type: application/json;charset=UTF-8
X-Csrf-Token: {{csrfToken}}
Origin: https://identity.getpostman.com
Referer: https://identity.getpostman.com/login

{"username":"{{username}}","password":"{{password}}"}
```

