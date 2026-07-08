# Vulnerability: Jeedom - Default Login
**Classification:** JEEDOM
**Source:** Nuclei Template (`jeedom-default-login.yaml`)

## Description
Jeedom default login has been detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /core/ajax/user.ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=login&username={{username}}&password={{password}}&twoFactorCode=&storeConnection=0

GET /index.php?v=d&p=dashboard HTTP/1.1
Host: {{Hostname}}
```

