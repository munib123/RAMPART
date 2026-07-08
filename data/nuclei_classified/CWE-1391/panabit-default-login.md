# Vulnerability: Panabit Gateway - Default Login
**Classification:** CWE-1391
**Source:** Nuclei Template (`panabit-default-login.yaml`)

## Description
Panabit Gateway default credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/userverify.cgi HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAjZMsILtbrBp8VbC
Referer: {{BaseURL}}/login/login.htm
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

------WebKitFormBoundaryAjZMsILtbrBp8VbC
Content-Disposition: form-data; name="username"

{{username}}
------WebKitFormBoundaryAjZMsILtbrBp8VbC
Content-Disposition: form-data; name="password"

{{password}}
------WebKitFormBoundaryAjZMsILtbrBp8VbC--
```

