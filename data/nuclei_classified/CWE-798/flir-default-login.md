# Vulnerability: Flir Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`flir-default-login.yaml`)

## Description
Flir default login credentials (admin/admin) were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/dologin HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

user_name={{username}}&user_password={{password}}
```

