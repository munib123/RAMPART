# Vulnerability: Spectracom Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`spectracom-default-login.yaml`)

## Description
Spectracom default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /users/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

data%5Bbutton%5D=submit&data%5BUser%5D%5Busername%5D={{username}}&data%5BUser%5D%5Bpassword%5D={{password}}
```

