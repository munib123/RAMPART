# Vulnerability: Apache Superset - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`superset-default-login.yaml`)

## Description
Apache Superset instance discovered using weak default credentials, allows the attacker to gain admin privilege.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/
POST /api/v1/security/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","provider":"db","refresh":true}
```

