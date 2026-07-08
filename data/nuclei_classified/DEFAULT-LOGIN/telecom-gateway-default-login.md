# Vulnerability: Telecom Gateway - Default Admin Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`telecom-gateway-default-login.yaml`)

## Description
Telecom Gateway default admin login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /manager/login.php HTTP/1.1
Host: {{Hostname}}

Name={{username}}&Pass={{password}}
```

