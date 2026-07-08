# Vulnerability: Panabit iXCache - Default Admin Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`panabit-ixcache-default-login.yaml`)

## Description
Panabit iXCache default admin login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/userverify.cgi HTTP/1.1
Host: {{Hostname}}

username={{username}}&password={{password}}
```

