# Vulnerability: DragonFly Public - Signup Enabled
**Classification:** DRAGONFLY
**Source:** Nuclei Template (`dragonfly-public-signup.yaml`)

## Description
Dragonfly public registration is enabled was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/users/signup HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"name":"{{username}}","password":"{{password}}","email":"{{email}}","passwordT":"{{password}}"}
```

