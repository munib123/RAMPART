# Vulnerability: RiteCMS - Default Login
**Classification:** RITECMS
**Source:** Nuclei Template (`ritecms-default-login.yaml`)

## Description
RiteCMS Default Credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{path}}admin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&userpw={{password}}
```

