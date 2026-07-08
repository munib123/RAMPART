# Vulnerability: Supermicro Ipmi - Default Admin Login
**Classification:** SUPERMICRO
**Source:** Nuclei Template (`supermicro-default-login.yaml`)

## Description
Supermicro Ipmi default admin login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cgi/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

name={{user}}&pwd={{pass}}
```

