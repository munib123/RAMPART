# Vulnerability: ERPNext - Default Login
**Classification:** ERPNEXT
**Source:** Nuclei Template (`erpnext-default-login.yaml`)

## Description
Detects ERPNext installations that use the default Administrator/admin login credentials. This misconfiguration grants attackers full administrative access to the system.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

cmd=login&usr={{username}}&pwd={{password}}&device=desktop
```

