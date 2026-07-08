# Vulnerability: secnet ac - Default Admin Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`secnet-ac-default-login.yaml`)

## Description
secnet ac default admin credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password={{password}}
```

