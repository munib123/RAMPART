# Nuclei Template: Empire C2 / Starkiller Interface - Default Login
**Template ID:** empirec2-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`empirec2-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Empire C2 / Starkiller Default Administrator Credentials Discovered.

## Steps to reproduce / Exploit Payload
```http
POST /token HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoZwyedGcQU4FrcFV
Accept: application/json, text/plain, */*

------WebKitFormBoundaryoZwyedGcQU4FrcFV
Content-Disposition: form-data; name="username"

{{username}}
------WebKitFormBoundaryoZwyedGcQU4FrcFV
Content-Disposition: form-data; name="password"

{{password}}
------WebKitFormBoundaryoZwyedGcQU4FrcFV--

POST /api/admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}"}
```

## References
- https://github.com/BC-SECURITY/Empire
- https://github.com/BC-SECURITY/empire-docs/blob/main/restful-api/README.md
