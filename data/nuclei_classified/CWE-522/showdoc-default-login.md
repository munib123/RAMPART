# Vulnerability: Showdoc Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`showdoc-default-login.yaml`)

## Description
Showdoc default credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /server/index.php?s=/api/user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

username={{username}}&password={{password}}&v_code=
```

